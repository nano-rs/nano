// SPDX-License-Identifier: AGPL-3.0-or-later

//! Whether a rule's result rows can carry a `source_type` the rule itself
//! wrote (NAN-5227).
//!
//! The scoping stamp trusts a row's per-event `source_type` as its origin.
//! That is only sound while the value is the base-search column. Any stage
//! that can assign a field named `source_type` (`eval`, `rename … AS`,
//! `table … AS`, an aggregation alias, `lookup … OUTPUT`, `rex`, `spath`,
//! `fillnull`, …) lets the rule relabel its rows, so the engine must not
//! trust that value and stamps provenance from the base search instead.
//!
//! The classification is structural and exhaustive: a new `Command` variant
//! is a compile error here instead of a silent "trusted". Commands whose
//! output fields are not modelled precisely are classified as writers, which
//! only costs a companion query.

use crate::query::{Aggregation, Command, Query, RexMode};

const FIELD: &str = "source_type";

fn is_source_type(name: &str) -> bool {
    name.trim().eq_ignore_ascii_case(FIELD)
}

fn aggregation_writes(aggregations: &[Aggregation]) -> bool {
    aggregations.iter().any(|agg| match agg.alias.as_deref() {
        Some(alias) => is_source_type(alias),
        // An unaliased aggregation over the field may be projected under the
        // field's own name; treat it as a writer.
        None => agg.field.as_deref().is_some_and(is_source_type),
    })
}

/// True when `command` can put a value into a result field named
/// `source_type` that is not the base-search column.
pub(crate) fn command_may_write_source_type(command: &Command) -> bool {
    match command {
        // Row filters and reorders: values pass through untouched.
        Command::Where { .. }
        | Command::Sort { .. }
        | Command::Head { .. }
        | Command::Tail { .. }
        | Command::Dedup { .. }
        | Command::Sample { .. }
        | Command::Reverse
        | Command::Fields { .. }
        | Command::Top { .. }
        | Command::Rare { .. } => false,

        Command::Eval { assignments } => assignments.iter().any(|a| is_source_type(&a.field)),
        Command::Rename { mappings } => mappings.iter().any(|m| is_source_type(&m.to)),
        Command::Table { fields } => fields
            .iter()
            .any(|f| f.alias.as_deref().is_some_and(is_source_type)),
        Command::Bin { alias, .. } => alias.as_deref().is_some_and(is_source_type),
        Command::Stats { aggregations, .. }
        | Command::Chart { aggregations, .. }
        | Command::StreamStats { aggregations, .. }
        | Command::EventStats { aggregations, .. }
        | Command::Timechart { aggregations, .. } => aggregation_writes(aggregations),
        Command::Lookup {
            output_fields,
            output_renames,
            ..
        } => match output_fields {
            // No OUTPUT list: every lookup column is written.
            None => true,
            Some(fields) => {
                fields.iter().any(|f| is_source_type(f))
                    || output_renames.iter().any(|r| is_source_type(&r.to))
            }
        },

        // Extraction stages write only the fields they name.
        Command::Rex {
            field,
            pattern,
            mode,
        } => match mode {
            RexMode::Extract => crate::query::clickhouse_sql_gen::extract_named_groups(pattern)
                .iter()
                .any(|g| is_source_type(g)),
            RexMode::Sed { .. } => is_source_type(field.as_deref().unwrap_or("message")),
        },
        Command::Fillnull { fields, .. } => match fields {
            None => true,
            Some(fields) => fields.iter().any(|f| is_source_type(f)),
        },
        Command::Mvexpand { field, .. } => is_source_type(field),
        Command::Spath { output, path, .. } => match (output, path) {
            (Some(output), _) => is_source_type(output),
            // Without `output=`, the value lands under the path's last segment;
            // without a path, every key is extracted.
            (None, Some(path)) => path
                .rsplit(['.', '/', '{', '}'])
                .find(|seg| !seg.is_empty())
                .is_none_or(is_source_type),
            (None, None) => true,
        },

        // Not modelled precisely: assume they can write the field.
        Command::Transaction { .. }
        | Command::Append { .. }
        | Command::Join { .. }
        | Command::Format { .. }
        | Command::Return { .. }
        | Command::Risk { .. }
        | Command::Prevalence { .. }
        | Command::Sequence { .. }
        | Command::Funnel { .. }
        | Command::Anomaly { .. }
        | Command::InputLookup { .. }
        | Command::Tree { .. }
        | Command::ResolveIdentity { .. }
        | Command::Asset { .. }
        | Command::Cloud { .. }
        | Command::Lateral { .. }
        | Command::Ai { .. }
        | Command::Output { .. }
        | Command::Services
        | Command::Service { .. }
        | Command::Trace { .. }
        | Command::Metric { .. }
        | Command::Retro { .. }
        | Command::Baseline { .. } => true,
    }
}

/// True when any stage of `query` can write `source_type`.
pub(crate) fn query_may_write_source_type(query: &Query) -> bool {
    match query {
        Query::Search(_) => false,
        Query::Piped { source, command } => {
            command_may_write_source_type(command) || query_may_write_source_type(source)
        }
    }
}

/// True when any scan of `query` other than the base search exists (a
/// subsearch in the base expression or in any stage). The base-search
/// companion cannot attribute rows such scans produce.
pub(crate) fn query_has_subsearch(query: &Query) -> bool {
    use crate::search::query_processing::query_manipulation::{
        command_has_subsearch, search_expr_has_subsearch,
    };
    match query {
        Query::Search(expr) => search_expr_has_subsearch(expr),
        Query::Piped { source, command } => {
            command_has_subsearch(command) || query_has_subsearch(source)
        }
    }
}

/// The provenance plan for one rule's rows.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct RowProvenance {
    /// The rows' `source_type` values may be rule-written.
    pub untrusted_source_type: bool,
    /// A subsearch contributes rows the base-search companion cannot attribute.
    pub has_subsearch: bool,
}

impl RowProvenance {
    /// Classify a rule query. Unparseable text fails closed.
    pub(crate) fn for_rule_query(rule_query: &str) -> Self {
        match crate::query::parse_query(rule_query) {
            Ok(query) => Self {
                untrusted_source_type: query_may_write_source_type(&query),
                has_subsearch: query_has_subsearch(&query),
            },
            Err(_) => Self {
                untrusted_source_type: true,
                has_subsearch: true,
            },
        }
    }
}

/// Field a rule-written `source_type` is kept under once it is no longer
/// treated as the row's origin.
pub(crate) const RULE_SOURCE_TYPE_FIELD: &str = "rule_source_type";

/// Move a rule-written `source_type` out of the origin field, so every reader
/// falls back to the engine's `_nano_source_types` stamp. The value stays in
/// the row under [`RULE_SOURCE_TYPE_FIELD`] for the analyst.
pub(crate) fn demote_rule_source_type(event: &mut serde_json::Value) {
    if let Some(obj) = event.as_object_mut() {
        if let Some(value) = obj.remove(FIELD) {
            obj.insert(RULE_SOURCE_TYPE_FIELD.to_string(), value);
        }
    }
}

#[cfg(test)]
#[path = "provenance_tests.rs"]
mod tests;
