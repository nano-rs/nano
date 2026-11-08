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
mod paginated;
mod query_execution;
mod query_management;
mod sql_helpers;
mod types;

// Re-export all public items for backward compatibility
pub use sql_helpers::{
    escape_question_marks_in_strings, inject_limit_offset, wrap_query_for_count,
    wrap_query_with_pagination,
};
pub(crate) use paginated::is_first_page;
pub(crate) use sql_helpers::{
    raw_sql_needs_skip_index_guard, wrap_aggregation_with_pagination, BoundedCountInput,
};
pub use types::{ClickHouseExecutor, ClickHouseLogReadRow};
pub(crate) use types::with_query_options;
