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

/// NAN-5697: the risk grain's per-row key. A risk notable is attributed to the
/// findings of the entity its row names, which is only sound while `entity`
/// is the grain's own column.
pub(crate) const RISK_ENTITY_FIELD: &str = "entity";

fn aggregation_writes(aggregations: &[Aggregation], is_field: &impl Fn(&str) -> bool) -> bool {
    aggregations.iter().any(|agg| match agg.alias.as_deref() {
        Some(alias) => is_field(alias),
        // An unaliased aggregation over the field may be projected under the
        // field's own name; treat it as a writer.
        None => agg.field.as_deref().is_some_and(is_field),
    })
}

/// True when `command` can put a value into a result field named `field`
/// (`source_type`, or NAN-5697's risk grain `entity`) that is not the
/// base-search column.
pub(crate) fn command_may_write_field(command: &Command, field: &str) -> bool {
    let is_field = |name: &str| name.trim().eq_ignore_ascii_case(field);
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

        Command::Eval { assignments } => assignments.iter().any(|a| is_field(&a.field)),
        Command::Rename { mappings } => mappings.iter().any(|m| is_field(&m.to)),
        Command::Table { fields } => fields
            .iter()
            .any(|f| f.alias.as_deref().is_some_and(is_field)),
        Command::Bin { alias, .. } => alias.as_deref().is_some_and(is_field),
        Command::Stats { aggregations, .. }
        | Command::Chart { aggregations, .. }
        | Command::StreamStats { aggregations, .. }
        | Command::EventStats { aggregations, .. }
        | Command::Timechart { aggregations, .. } => aggregation_writes(aggregations, &is_field),
        Command::Lookup {
            output_fields,
            output_renames,
            ..
        } => match output_fields {
            // No OUTPUT list: every lookup column is written.
            None => true,
            Some(fields) => {
                fields.iter().any(|f| is_field(f))
                    || output_renames.iter().any(|r| is_field(&r.to))
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
                .any(|g| is_field(g)),
            RexMode::Sed { .. } => is_field(field.as_deref().unwrap_or("message")),
        },
        Command::Fillnull { fields, .. } => match fields {
            None => true,
            Some(fields) => fields.iter().any(|f| is_field(f)),
        },
        Command::Mvexpand { field, .. } => is_field(field),
        Command::Spath { output, path, .. } => match (output, path) {
            (Some(output), _) => is_field(output),
            // Without `output=`, the value lands under the path's last segment;
            // without a path, every key is extracted.
            (None, Some(path)) => path
                .rsplit(['.', '/', '{', '}'])
                .find(|seg| !seg.is_empty())
                .is_none_or(is_field),
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

/// NAN-5697: true when `command` keeps every risk row's data confined to that
/// row's own entity, so the row may be attributed to that entity's findings.
///
/// An ALLOW-list, exhaustive by construction: a stage that writes `entity`,
/// that selects rows by rank (`head`/`tail`/`dedup`/`sample`), or that can
/// combine values across rows (`eventstats`, `streamstats`, `top`,
/// `rare`, `chart`, `stats` not grouped by `entity` alone, …) can put another
/// entity's (possibly restricted) data onto a row that keeps its own `entity`.
/// Every such stage, and every stage not modelled precisely, returns `false`,
/// which attributes the rows to the whole findings window instead (a superset).
/// A new `Command` variant is a compile error here.
pub(crate) fn command_keeps_risk_rows_entity_local(command: &Command) -> bool {
    let is_entity = |name: &str| name.trim().eq_ignore_ascii_case(RISK_ENTITY_FIELD);
    match command {
        // Per-row predicates, reorders, projections and per-row value stages:
        // each output row is built from one input row, and whether it survives
        // depends only on its own values (subsearches are handled by
        // `has_subsearch`, which fails closed before attribution). A reorder
        // alone cannot change which rows survive.
        Command::Where { .. }
        | Command::Sort { .. }
        | Command::Reverse
        | Command::Fields { .. }
        | Command::Eval { .. }
        | Command::Rename { .. }
        | Command::Table { .. }
        | Command::Bin { .. }
        | Command::Rex { .. }
        | Command::Fillnull { .. }
        | Command::Mvexpand { .. }
        | Command::Spath { .. } => !command_may_write_field(command, RISK_ENTITY_FIELD),

        // `stats … by entity` aggregates within one entity (the grain has one
        // row per entity); any other grouping mixes entities.
        Command::Stats { aggregations, group_by } => {
            matches!(group_by.as_deref(), Some([only]) if is_entity(only))
                && !aggregation_writes(aggregations, &is_entity)
        }

        // Rank-dependent selection: which rows survive depends on the OTHER
        // rows' values or order (an explicit `sort`, or the grain's default
        // `last_finding_at` order), so a surviving row reveals how it ranks
        // against entities that may be denied. `sample` is included
        // conservatively.
        Command::Head { .. }
        | Command::Tail { .. }
        | Command::Dedup { .. }
        | Command::Sample { .. }
        // Cross-row aggregation, enrichment from other data, or not modelled.
        | Command::Chart { .. }
        | Command::StreamStats { .. }
        | Command::EventStats { .. }
        | Command::Timechart { .. }
        | Command::Top { .. }
        | Command::Rare { .. }
        | Command::Lookup { .. }
        | Command::Transaction { .. }
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
        | Command::Baseline { .. } => false,
    }
}

/// NAN-5697: true when every stage of `query` keeps risk rows entity-local.
pub(crate) fn query_keeps_risk_rows_entity_local(query: &Query) -> bool {
    match query {
        Query::Search(_) => true,
        Query::Piped { source, command } => {
            command_keeps_risk_rows_entity_local(command) && query_keeps_risk_rows_entity_local(source)
        }
    }
}

/// True when any stage of `query` can write `source_type`.
pub(crate) fn query_may_write_source_type(query: &Query) -> bool {
    query_may_write_field(query, FIELD)
}

/// True when any stage of `query` can write `field`.
pub(crate) fn query_may_write_field(query: &Query, field: &str) -> bool {
    match query {
        Query::Search(_) => false,
        Query::Piped { source, command } => {
            command_may_write_field(command, field) || query_may_write_field(source, field)
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
    /// NAN-5697: every stage keeps each risk row's data confined to its own
    /// `entity` (none writes `entity` or combines rows), so a risk row may be
    /// attributed to the findings of the entity it names. Otherwise rows are
    /// attributed to the whole findings window.
    pub risk_rows_entity_local: bool,
    /// A subsearch contributes rows the base-search companion cannot attribute.
    pub has_subsearch: bool,
}

impl RowProvenance {
    /// Classify a rule query. Unparseable text fails closed.
    pub(crate) fn for_rule_query(rule_query: &str) -> Self {
        match crate::query::parse_query(rule_query) {
            Ok(query) => Self {
                untrusted_source_type: query_may_write_source_type(&query),
                risk_rows_entity_local: query_keeps_risk_rows_entity_local(&query),
                has_subsearch: query_has_subsearch(&query),
            },
            Err(_) => Self {
                untrusted_source_type: true,
                risk_rows_entity_local: false,
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
