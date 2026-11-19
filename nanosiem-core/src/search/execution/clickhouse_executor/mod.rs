// SPDX-License-Identifier: AGPL-3.0-or-later

//! ClickHouse query executor
//!
//! This module provides the ClickHouse implementation of the SqlExecutor trait.
//! It is organized into focused submodules by concern:
//!
//! - `types` - Core types: `ClickHouseLogReadRow`, `ClickHouseExecutor`
//! - `sql_helpers` - Free functions for SQL manipulation
//! - `query_execution` - Core query execution methods (typed, dynamic, count)
//! - `field_stats` - Field statistics and field value queries
//! - `query_management` - Query cancellation, progress tracking, quick counts
//! - `paginated` - Paginated execution, streaming, and `SqlExecutor` trait impl

mod field_stats;
pub(crate) use field_stats::EXT_FIELD_NAMES_OUTPUT_LIMIT;
mod paginated;
mod query_execution;
mod query_management;
mod sql_helpers;
mod types;
#[cfg(test)]
mod utf8_response_tests;
#[cfg(test)]
mod max_query_size_wiring_tests;
#[cfg(test)]
mod max_query_size_profile_guard_tests;

// Re-export all public items for backward compatibility
pub use sql_helpers::{
    escape_question_marks_in_strings, inject_limit_offset, wrap_query_for_count,
    wrap_query_with_pagination,
};
pub(crate) use paginated::{is_first_page, paged_total_estimate};
pub(crate) use sql_helpers::{
    build_count_query, is_aggregation_query, raw_sql_needs_skip_index_guard,
    wrap_aggregation_with_pagination, BoundedCountInput,
};
pub use types::{ClickHouseExecutor, ClickHouseLogReadRow};
pub(crate) use types::{
    max_query_size_for, CLICKHOUSE_DEFAULT_MAX_QUERY_SIZE, MAX_QUERY_SIZE_CEILING,
    MAX_QUERY_SIZE_HEADROOM,
};
pub(crate) use types::with_query_options;
