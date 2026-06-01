// SPDX-License-Identifier: AGPL-3.0-or-later

//! Shared SQL-generation types (`TimeRange`, `SqlGenError`).
//!
//! These are consumed by the ClickHouse SQL generator (`super::clickhouse_sql_gen`)
//! and re-exported from `crate::query`. The former PostgreSQL `SqlGenerator` that
//! lived here was removed in NAN-1162 — ClickHouse is the only log backend
//! (PostgreSQL is metadata-only); PG-only query mode was removed in NAN-800.

use chrono::{DateTime, Utc};
use thiserror::Error;

/// Time range for query execution
#[derive(Debug, Clone)]
pub struct TimeRange {
    pub start: DateTime<Utc>,
    pub end: DateTime<Utc>,
}

impl TimeRange {
    pub fn new(start: DateTime<Utc>, end: DateTime<Utc>) -> Self {
        Self { start, end }
    }
}

/// Errors that can occur during SQL generation
#[derive(Debug, Error)]
pub enum SqlGenError {
    #[error("Empty query")]
    EmptyQuery,
    #[error("Invalid field name: {0}")]
    InvalidFieldName(String),
    #[error("Unsupported operation: {0}")]
    UnsupportedOperation(String),
    #[error("Internal error: {0}")]
    Internal(String),
    #[error("Invalid query: {0}")]
    InvalidQuery(String),
}
