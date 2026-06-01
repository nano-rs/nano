// SPDX-License-Identifier: AGPL-3.0-or-later

//! Query execution utilities for SQL validation and database operations

pub mod clickhouse_executor;
pub mod traits;
pub mod validation;

// Re-export commonly used items
pub use clickhouse_executor::{
    escape_question_marks_in_strings, ClickHouseExecutor, ClickHouseLogReadRow,
};
pub use traits::SqlExecutor;
pub use validation::{inject_audit_filter, validate_sql_query};
