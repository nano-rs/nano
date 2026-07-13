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
pub(crate) mod clickhouse_sql_gen;
mod parser;
mod pretty_print;
mod sql_gen;
pub mod validation;

pub use ast::*;
pub(crate) use clickhouse_sql_gen::escape_identifier;
// Re-exported so `SchemaProfile::column_sql`'s JsonPath arm emits the SAME
// native-subcolumn access as `field_access_expr` (NAN-1426 lockstep). This
// replaced the `escape_string` re-export, whose only external consumer was
// that arm's hand-rolled JSONExtractString emission.
pub(crate) use clickhouse_sql_gen::json_tail_access_sql;
// Re-exported so `SchemaProfile::column_sql`'s MapKey arm (spans/metrics attribute
// tail) emits the SAME native `Map` subscript as `field_access_expr` (NAN-1555
// lockstep — mirrors the json_tail_access_sql lockstep above).
pub(crate) use clickhouse_sql_gen::map_tail_access_sql;
// `pub` (not `pub(crate)`): the DDL↔Rust column drift gate
// (`tests/logs_ddl_column_consistency.rs`, NAN-1623) is an integration test and
// consumes this canonical list to assert it equals the DDL's MATERIALIZED set.
pub use clickhouse_sql_gen::MATERIALIZED_COLUMNS;
// Re-exported so `crate::schema::udm::UdmProfile::canonicalize` delegates to the
// canonical alias map rather than duplicating it (OCSF Phase 2, NAN-1241).
pub(crate) use clickhouse_sql_gen::normalize_field_name;
// Re-exported for `crate::schema::udm::UdmProfile` so it references the canonical
// const arrays for byte-for-byte parity rather than copying values (NAN-1244).
pub(crate) use clickhouse_sql_gen::{
    LOWERCASE_NORMALIZED_FIELDS, NUMERIC_UDM_FIELDS, PREWHERE_FIELDS, UUID_FIELDS,
};
// `pub` (not `pub(crate)`): consumed by the DDL↔Rust column drift gate
// (`tests/logs_ddl_column_consistency.rs`, NAN-1623) — see MATERIALIZED_COLUMNS above.
pub use clickhouse_sql_gen::EXPLICIT_COLUMNS;
pub use clickhouse_sql_gen::{ClickHouseSqlGenerator, QueryOptions};
// OTLP observability (NAN-1528): dataset selector + trace/metrics fetch SQL the
// search/api layer calls to target the `otel_spans`/`otel_metrics` tables.
pub use clickhouse_sql_gen::otel::{
    metric_names_sql, metric_timeseries_sql, recent_traces_sql, trace_by_id_sql, Dataset,
    MetricRollup, TraceListFilters,
};
// Observability console (NAN-1536): services overview / service detail RED
// timeseries + endpoints + exemplars, and SLO spans-based compute.
pub use clickhouse_sql_gen::otel::{
    service_endpoints_sql, service_exemplars_sql, service_red_timeseries_sql,
    services_overview_sql, services_sparkline_sql, slo_compute_sql, ServicesOverviewFilters,
    ServicesSort, SliKind,
};
// Observability console (NAN-1537/1538): Infra host inventory, RUM web-vitals /
// page-views / top-pages / recent-errors, and synthetic-check results summaries.
pub use clickhouse_sql_gen::otel::{
    infra_hosts_sql, rum_pageviews_series_sql, rum_recent_errors_sql, rum_top_pages_sql,
    rum_web_vitals_sql, synthetic_history_sql, synthetic_summary_sql, InfraHostsFilters, RumFilters,
};
// Observability ↔ security convergence (NAN-1542): a service's entities + the
// detection signals firing against them.
pub use clickhouse_sql_gen::otel::{
    security_signals_for_entities_sql, service_entities_sql, SERVICE_ENTITY_CAP,
};
// Metrics v2 (NAN-1540): the query builder (agg / group_by / tag filters), the
// monitor-eval scalar form, and tag-key/value enumeration.
pub use clickhouse_sql_gen::otel::{
    metric_scalar_sql, metric_tag_keys_sql, metric_tag_values_sql, metric_timeseries_v2_sql,
    valid_tag_key, MetricAgg, MetricQuery, MetricTagFilter,
};
pub use parser::{parse_query, ParseError};
pub(crate) use parser::extract_time_modifier_tokens;
pub use pretty_print::PrettyPrint;
pub use sql_gen::{SqlGenError, TimeRange};
pub use validation::{
    // Query cost analysis (query cost analysis)
    analyze_query_cost,
    collect_derived_fields,
    contains_aggregation,
    contains_join,
    contains_risk_command,
    is_aggregation_command,
    pre_aggregation_subquery,
    suggest_similar_fields,
    validate_field_name,
    validate_field_name_format,
    validate_query_fields,
    validate_query_fields_with_profile,
    FieldValidationError,
    QueryCostAnalysis,
    QueryWarning,
    WarningSeverity,
};

/// Sanitize an untrusted value for safe interpolation inside an nPL
/// **double-quoted** string literal, e.g. `field="<value>"`.
///
/// The nPL parser does NOT honor backslash escaping: `double_quoted_string`
/// (`query::parser::values`) is `take_while(|c| c != '"')`, so the first `"`
/// always terminates the literal and a backslash is a literal character. That
/// is deliberate (NAN-1157) so Windows paths like `"C:\Windows\"` parse. There
/// is therefore no escape sequence that can neutralize a `"`; the only safe
/// option is to STRIP the characters that could terminate the literal (or, if a
/// value were ever embedded unquoted, introduce a new pipe stage). Do NOT
/// rewrite this as a backslash-escaper — that is a no-op against this grammar.
///
/// Removes `"` (the breakout char) plus `|`, backtick, and newlines as defense
/// in depth; KEEPS `\` (so Windows paths still match) and `'` (so usernames like
/// `O'Connor` still match) since both are inert inside a double-quoted literal.
/// Callers must wrap the result in double quotes.
///
/// This is the single source of truth for both the shadow-investigation pivots
/// (`cases::shadow_investigation`) and the pivt tool-loop (`melod`) so the two
/// can't drift (NAN-1740 / NAN-1744).
pub fn sanitize_npl_quoted_value(value: &str) -> String {
    value
        .chars()
        .filter(|c| !matches!(c, '"' | '|' | '`' | '\n' | '\r'))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::sanitize_npl_quoted_value as sanitize;

    #[test]
    fn strips_breakout_and_inject_chars() {
        // The canonical injection payload: close the quote, inject a pipe stage.
        let out = sanitize("evil\" | where 1=0 \"");
        assert!(!out.contains('"'), "quote removed: {out:?}");
        assert!(!out.contains('|'), "pipe removed: {out:?}");
        // Backtick and newlines are stripped too.
        assert_eq!(sanitize("a`b\nc\rd"), "abcd");
    }

    #[test]
    fn keeps_backslash_and_apostrophe() {
        // Windows paths and apostrophe usernames must survive so pivots match.
        assert_eq!(sanitize(r"C:\Windows\System32"), r"C:\Windows\System32");
        assert_eq!(sanitize(r"DOMAIN\Administrator"), r"DOMAIN\Administrator");
        assert_eq!(sanitize("O'Connor"), "O'Connor");
    }
}
