// SPDX-License-Identifier: AGPL-3.0-or-later

//! SQL Generator for converting piped query AST to PostgreSQL SQL
//!
//! This module generates PostgreSQL SQL from the piped query AST, using:
//! - BM25 operators (@@@ ) for keyword searches via pg_search
//! - JSONB operators for field filters on metadata
//! - CTEs for multi-stage piped queries
//! - Standard SQL aggregations and ordering
//!
//! ## Submodules
//!
//! - [`field_utils`] - Field name resolution, escaping, and JSONB path generation
//! - [`eval_functions`] - Eval expression to SQL conversion
//! - [`search_expr`] - Search expression and WHERE clause generation
//! - [`commands`] - Individual command SQL generation
//! - [`query_gen`] - Top-level query generation and CTE assembly
//! - [`aggregation`] - Stats and timechart aggregation SQL

mod aggregation;
mod commands;
mod eval_functions;
pub mod field_utils;
mod query_gen;
mod search_expr;

use chrono::{DateTime, Utc};
use thiserror::Error;

use super::ast::*;

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

/// SQL Generator for converting Query AST to PostgreSQL
#[derive(Clone)]
pub struct SqlGenerator {
    /// Table name for logs
    table_name: String,
}

impl Default for SqlGenerator {
    fn default() -> Self {
        Self::new()
    }
}

impl SqlGenerator {
    /// Create a new SQL generator with default table name "logs"
    pub fn new() -> Self {
        Self {
            table_name: "logs".to_string(),
        }
    }

    /// Create a new SQL generator with a custom table name
    pub fn with_table(table_name: impl Into<String>) -> Self {
        Self {
            table_name: table_name.into(),
        }
    }
}

/// Internal stage representation for query processing
pub(super) enum QueryStage<'a> {
    Search(&'a SearchExpr),
    Command(&'a Command),
}

/// Context for SQL generation
pub(super) struct GeneratorContext<'a> {
    pub(super) table_name: &'a str,
    pub(super) time_range: &'a TimeRange,
    pub(super) current_stage: usize,
}

impl<'a> GeneratorContext<'a> {
    pub(super) fn new(table_name: &'a str, time_range: &'a TimeRange) -> Self {
        Self {
            table_name,
            time_range,
            current_stage: 0,
        }
    }
}
