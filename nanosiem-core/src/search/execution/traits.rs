// SPDX-License-Identifier: AGPL-3.0-or-later

//! Traits for database query execution
//!
//! This module defines the common interfaces for executing queries across
//! different database backends (PostgreSQL, ClickHouse).

use crate::search::SearchError;
use std::future::Future;

/// Trait for executing SQL queries and returning results as JSON
pub trait SqlExecutor: Send + Sync {
    /// Execute a SQL query with pagination
    ///
    /// Returns a tuple of (results, total_count) where:
    /// - results: Vector of JSON objects representing rows
    /// - total_count: Total number of rows matching the query (before pagination)
    ///
    /// `preserve_columns`: keep every column the query selected, even when empty.
    /// Grouped rows (`stats … by`, `top`, `rare`) must set this — pruning an
    /// empty group-by key reports the bucket as a bare count (NAN-1848). Raw
    /// event rows pass `false` so the wide, mostly-empty UDM columns are trimmed.
    fn execute_sql(
        &self,
        sql: &str,
        limit: usize,
        offset: usize,
        preserve_columns: bool,
    ) -> impl Future<Output = Result<(Vec<serde_json::Value>, u64), SearchError>> + Send;

    /// Execute a SQL query and return all results as JSON (no pagination)
    fn execute_sql_to_json(
        &self,
        sql: &str,
    ) -> impl Future<Output = Result<Vec<serde_json::Value>, SearchError>> + Send;
}
