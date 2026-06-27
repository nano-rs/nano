// SPDX-License-Identifier: AGPL-3.0-or-later

//! Lookup Module
//!
//! Provides lookup table management for search enrichment.
//! Supports creating, querying, and managing reference data tables.
//!
//! Requirements: 2.1, 2.2, 2.3, 2.4, 2.5, 2.7, 3.1, 3.2, 3.3, 3.4, 3.5, 5.3, 5.4

pub mod backfill;
pub mod clickhouse_repository;
pub mod postgres_repository;
pub mod repository;
pub mod sanitize;
pub mod service;
pub mod snowflake;
pub mod types;

pub use backfill::{
    backfill_pg_to_clickhouse, is_backfill_in_progress, BackfillReport, TableBackfillResult,
};
pub use clickhouse_repository::ClickHouseLookupRepository;
pub use postgres_repository::PostgresLookupRepository;
pub use repository::{
    LookupRepository, LookupRepositoryError, LookupStorageBackend, LookupStore, RuleReferenceRow,
};
pub use sanitize::{sanitize_identifier, sanitize_identifiers};
pub use service::{LookupError, LookupService};
pub use types::{
    BatchLookupQuery, BatchLookupResult, ColumnTypeOverride, LookupColumn, LookupHistoryEntry,
    LookupHistoryKind, LookupQuery, LookupResult, LookupRowsPage, LookupTable, LookupTableCreator,
    LookupUsage, NewLookupTable, LOOKUP_TABLE_PREFIX, MAX_LOOKUP_TABLE_ROWS,
};
