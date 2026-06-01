// SPDX-License-Identifier: AGPL-3.0-or-later

//! Query parsing and SQL generation for NanoSIEM
//!
//! This module provides:
//! - AST types for piped query syntax
//! - Parser using nom combinators
//! - Pretty-printer for AST to query string conversion
//! - SQL generator for PostgreSQL
//! - SQL generator for ClickHouse (`clickhouse_sql_gen`; `sql_gen` holds the shared
//!   `TimeRange`/`SqlGenError` types)

mod ast;
mod clickhouse_sql_gen;
mod parser;
mod pretty_print;
mod sql_gen;
pub mod validation;

pub use ast::*;
pub(crate) use clickhouse_sql_gen::is_explicit_column;
pub(crate) use clickhouse_sql_gen::MATERIALIZED_COLUMNS;
pub use clickhouse_sql_gen::{ClickHouseSqlGenerator, QueryOptions};
pub use parser::{parse_query, ParseError};
pub use pretty_print::PrettyPrint;
pub use sql_gen::{SqlGenError, TimeRange};
pub use validation::{
    // Query cost analysis (query cost analysis)
    analyze_query_cost,
    collect_derived_fields,
    contains_aggregation,
    contains_join,
    is_aggregation_command,
    pre_aggregation_subquery,
    suggest_similar_fields,
    validate_field_name,
    validate_field_name_format,
    validate_query_fields,
    FieldValidationError,
    QueryCostAnalysis,
    QueryWarning,
    WarningSeverity,
};

#[cfg(test)]
mod tests {}
