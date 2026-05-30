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

/// NAN-1029: default distributed DDL coordination timeout for every query the
/// migrator issues. ClickHouse's built-in default is 180s, which is too short
/// for real-world `ON CLUSTER` work on multi-shard prod data (index drops,
/// materializes, large CREATE TABLEs all routinely exceed it). 900s (15min)
/// is the same budget NAN-1028 applied per-statement; setting it at the
/// client level catches every code path (tracking, distributed-table sync,
/// numbered migrations, init.sql) without requiring each site to remember.
///
/// Per-query `SETTINGS distributed_ddl_task_timeout = N` clauses override
/// this default, so callers who genuinely want a shorter or longer budget
/// for a specific statement still can.
const MIGRATOR_DISTRIBUTED_DDL_TIMEOUT_SECS: &str = "900";

/// NAN-1030: per-query overall execution timeout for the migrator. CH's
/// default `max_execution_time` is 300s — enough for a normal user query,
/// way too short for an `ALTER TABLE ADD INDEX` that backfills a large
/// table or any real-world materialize on multi-TB prod data.
///
/// 1800s (30min) is large enough to fit a real index backfill on the
/// largest Saturn-scale tenants but still bounds a genuinely stuck query
/// so the deploy fails-fast instead of hanging indefinitely. NAN-1029's
/// 900s `distributed_ddl_task_timeout` sits inside this — coordinator ACK
/// has its own ceiling so we don't conflate the two failure modes.
const MIGRATOR_MAX_EXECUTION_TIME_SECS: &str = "1800";

impl ClickHouseMigrator {
    /// Create a new migrator with the given ClickHouse client
    pub fn new(client: clickhouse::Client, database: impl Into<String>) -> Self {
        let client = client
            .with_option(
                "distributed_ddl_task_timeout",
                MIGRATOR_DISTRIBUTED_DDL_TIMEOUT_SECS,
            )
            .with_option("max_execution_time", MIGRATOR_MAX_EXECUTION_TIME_SECS);
        Self {
            client,
            database: database.into(),
            is_cloud: None,
            cluster: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn migrator_constant_matches_per_statement_budget() {
        // The per-statement injection in NAN-1028 uses 900s. Keep the
        // client-level default in lockstep so behavior doesn't diverge.
        assert_eq!(MIGRATOR_DISTRIBUTED_DDL_TIMEOUT_SECS, "900");
    }

    #[test]
    fn migrator_max_execution_time_is_generous() {
        // NAN-1030: must exceed `distributed_ddl_task_timeout` so the DDL
        // coordinator gets a chance to time out cleanly first (clearer
        // diagnostics than a generic max_execution_time kill), AND must be
        // long enough for real index backfills on prod-scale data.
        let max_exec: u64 = MIGRATOR_MAX_EXECUTION_TIME_SECS.parse().unwrap();
        let ddl_timeout: u64 = MIGRATOR_DISTRIBUTED_DDL_TIMEOUT_SECS.parse().unwrap();
        assert!(
            max_exec > ddl_timeout,
            "max_execution_time={max_exec}s must exceed distributed_ddl_task_timeout={ddl_timeout}s"
        );
        assert!(max_exec >= 900, "max_execution_time={max_exec}s too short for real DDL");
    }

    #[test]
    fn migrator_new_does_not_panic_and_preserves_database() {
        // Smoke-test that wrapping the client with `with_option` doesn't
        // break construction. We can't introspect clickhouse::Client's
        // options directly (private), so this is the smallest assertion
        // we can make in pure-unit-test scope.
        let client = clickhouse::Client::default().with_url("http://localhost:8123");
        let migrator = ClickHouseMigrator::new(client, "test_db");
        assert_eq!(migrator.database, "test_db");
    }
}
