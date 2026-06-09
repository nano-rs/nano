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
pub(crate) use clickhouse_sql_gen::escape_identifier;
pub(crate) use clickhouse_sql_gen::escape_string;
pub(crate) use clickhouse_sql_gen::MATERIALIZED_COLUMNS;
// Re-exported so `crate::schema::udm::UdmProfile::canonicalize` delegates to the
// canonical alias map rather than duplicating it (OCSF Phase 2, NAN-1241).
pub(crate) use clickhouse_sql_gen::normalize_field_name;
// Re-exported for `crate::schema::udm::UdmProfile` so it references the canonical
// const arrays for byte-for-byte parity rather than copying values (NAN-1244).
pub(crate) use clickhouse_sql_gen::{
    EXPLICIT_COLUMNS, LOWERCASE_NORMALIZED_FIELDS, NUMERIC_UDM_FIELDS, PREWHERE_FIELDS, UUID_FIELDS,
};
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
