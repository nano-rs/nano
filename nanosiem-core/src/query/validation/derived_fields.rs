// SPDX-License-Identifier: AGPL-3.0-or-later

//! Derived field collection from pipeline commands
//!
//! Walks the parsed AST and collects field names that are produced by pipeline
//! commands (stats, eval, rename, rex, bin, etc.). These fields are valid
//! references in downstream pipeline stages even though they don't exist in
//! the UDM schema.

use crate::query::ast::{AggFunc, Aggregation, Command, Query, RexMode, SearchExpr};
use std::collections::HashSet;

/// Collect all field names created by pipeline commands in a query.
///
/// Walks the parsed AST and returns a `HashSet<String>` of field names that
/// are produced by commands like `stats`, `eval`, `rename`, `rex`, `bin`, etc.
/// These fields are valid references in downstream pipeline stages even though
/// they don't exist in the UDM schema.
///
/// Field names are returned in lowercase for case-insensitive matching.
pub fn collect_derived_fields(query: &Query) -> HashSet<String> {
    let mut fields = HashSet::new();
    collect_derived_fields_recursive(query, &mut fields);
    fields
}

/// Extract field names referenced in a search expression (for sequence condition auto-capture)
fn collect_fields_from_expr(expr: &SearchExpr) -> Vec<String> {
    let mut fields = Vec::new();
    match expr {
        SearchExpr::FieldFilter { field, .. }
        | SearchExpr::FieldFunctionFilter { field, .. }
        | SearchExpr::InList { field, .. } => {
            fields.push(field.clone());
        }
        SearchExpr::And(left, right) | SearchExpr::Or(left, right) => {
            fields.extend(collect_fields_from_expr(left));
            fields.extend(collect_fields_from_expr(right));
        }
        SearchExpr::Not(inner) | SearchExpr::Group(inner) => {
            fields.extend(collect_fields_from_expr(inner));
        }
        _ => {}
    }
    fields
}

fn collect_derived_fields_recursive(query: &Query, fields: &mut HashSet<String>) {
    match query {
        Query::Search(_) => {
            // Search expressions don't create new fields
        }
        Query::Piped { source, command } => {
            collect_derived_fields_recursive(source, fields);
            collect_command_output_fields(command, fields);
        }
    }
}

/// Get the default output name for an aggregation (mirrors clickhouse_sql_gen.rs alias logic).
fn get_aggregation_output_name(agg: &Aggregation) -> String {
    if let Some(alias) = &agg.alias {
        return alias.to_lowercase();
    }
    // count() with no field → "count"
    if agg.field.is_none() && agg.func == AggFunc::Count {
        return "count".to_string();
    }
    // values(field) / list(field) → "values_field" / "list_field"
    if matches!(agg.func, AggFunc::Values | AggFunc::List) {
        if let Some(field) = &agg.field {
            return format!("{}_{}", agg.func.as_str(), field).to_lowercase();
        }
    }
    // Everything else → function name ("dc", "sum", "avg", etc.)
    agg.func.as_str().to_lowercase()
}

/// Register the additional `{func}_{field}` reference alias codegen accepts for
/// un-aliased, field-bearing aggregations (NAN-1339, PR #2063): downstream
/// commands may reference `avg(bytes_in)` as `avg_bytes_in`, which
/// `collect_agg_reference_aliases` in `clickhouse_sql_gen::field_analysis`
/// remaps to the real output column. Must be called from EXACTLY the command
/// arms that remap covers — Stats, Chart, Timechart, EventStats. StreamStats is
/// deliberately excluded: the codegen remap doesn't cover it, so registering
/// the name here would only unmask a later codegen failure (NAN-1396).
fn insert_agg_reference_alias(agg: &Aggregation, fields: &mut HashSet<String>) {
    if agg.alias.is_none() {
        if let Some(field) = &agg.field {
            fields.insert(format!("{}_{}", agg.func.as_str(), field).to_lowercase());
        }
    }
}

pub(super) fn collect_command_output_fields(command: &Command, fields: &mut HashSet<String>) {
    match command {
        Command::Stats {
            aggregations,
            group_by,
        }
        | Command::Chart {
            aggregations,
            group_by,
        } => {
            for agg in aggregations {
                fields.insert(get_aggregation_output_name(agg));
                insert_agg_reference_alias(agg, fields);
            }
            if let Some(gb) = group_by {
                for f in gb {
                    fields.insert(f.to_lowercase());
                }
            }
        }
        Command::EventStats { aggregations, .. } => {
            for agg in aggregations {
                fields.insert(get_aggregation_output_name(agg));
                insert_agg_reference_alias(agg, fields);
            }
        }
        Command::StreamStats { aggregations, .. } => {
            // No `insert_agg_reference_alias` here: codegen's
            // `collect_agg_reference_aliases` does not remap `{func}_{field}`
            // for streamstats, so the only valid downstream name is the
            // output alias itself.
            for agg in aggregations {
                fields.insert(get_aggregation_output_name(agg));
            }
        }
        Command::Eval { assignments } => {
            for a in assignments {
                fields.insert(a.field.to_lowercase());
            }
        }
        Command::Rename { mappings } => {
            for m in mappings {
                fields.insert(m.to.to_lowercase());
            }
        }
        Command::Rex { pattern, mode, .. } => {
            if matches!(mode, RexMode::Extract) {
                // Extract named capture groups (?<name>...)  and  (?P<name>...)
                for cap in regex::Regex::new(r"\(\?(?:P?<([^>]+)>)")
                    .unwrap()
                    .captures_iter(pattern)
                {
                    if let Some(name) = cap.get(1) {
                        fields.insert(name.as_str().to_lowercase());
                    }
                }
            }
        }
        Command::Bin { field, alias, .. } => {
            if let Some(a) = alias {
                fields.insert(a.to_lowercase());
            } else if let Some(f) = field {
                fields.insert(f.to_lowercase());
            } else {
                fields.insert("time_bucket".to_string());
            }
        }
        Command::Top {
            field,
            show_count,
            show_percent,
            ..
        }
        | Command::Rare {
            field,
            show_count,
            show_percent,
            ..
        } => {
            fields.insert(field.to_lowercase());
            if *show_count {
                fields.insert("count".to_string());
            }
            if *show_percent {
                fields.insert("percent".to_string());
            }
        }
        Command::Timechart {
            aggregations,
            split_by,
            ..
        } => {
            fields.insert("time_bucket".to_string());
            for sb in split_by {
                fields.insert(sb.to_lowercase());
            }
            for agg in aggregations {
                fields.insert(get_aggregation_output_name(agg));
                insert_agg_reference_alias(agg, fields);
            }
        }
        Command::Risk { .. } => {
            fields.insert("risk_score".to_string());
            fields.insert("risk_factors".to_string());
            fields.insert("risk_level".to_string());
        }
        Command::Prevalence { enrich, .. } => {
            if *enrich {
                fields.insert("host_count".to_string());
                fields.insert("is_rare".to_string());
                fields.insert("prevalence_score".to_string());
                fields.insert("total_occurrences".to_string());
                fields.insert("prevalence_first_seen".to_string());
                fields.insert("prevalence_last_seen".to_string());
                fields.insert("prevalence_type".to_string());
                fields.insert("prevalence_artifact".to_string());
                // Legacy aliases
                fields.insert("hash_prevalence".to_string());
                fields.insert("domain_prevalence".to_string());
                fields.insert("hash_first_seen".to_string());
                fields.insert("domain_first_seen".to_string());
                fields.insert("first_seen".to_string());
                fields.insert("last_seen".to_string());
            }
        }
        Command::Lookup { output_fields, .. } => {
            if let Some(of) = output_fields {
                for f in of {
                    fields.insert(f.to_lowercase());
                }
            }
        }
        Command::Transaction {
            fields: tx_fields, ..
        } => {
            for f in tx_fields {
                fields.insert(f.to_lowercase());
            }
            fields.insert("duration".to_string());
            fields.insert("eventcount".to_string());
            fields.insert("transaction_start".to_string());
            fields.insert("transaction_end".to_string());
        }
        Command::Sequence {
            group_by,
            conditions,
            capture_fields,
            ..
        } => {
            for f in group_by {
                fields.insert(f.to_lowercase());
            }
            // Sequence produces step-prefixed fields for each condition:
            // - step{N}_time, step{N}_event_id (always)
            // - step{N}_{field} for capture_fields and auto-captured condition fields
            for (i, cond) in conditions.iter().enumerate() {
                let n = i + 1;
                fields.insert(format!("step{}_time", n));
                fields.insert(format!("step{}_event_id", n));
                for field in capture_fields {
                    fields.insert(format!("step{}_{}", n, field.to_lowercase()));
                }
                // Auto-captured fields from condition expressions
                let cond_fields = collect_fields_from_expr(cond);
                for field in &cond_fields {
                    fields.insert(format!("step{}_{}", n, field.to_lowercase()));
                }
            }
            fields.insert("sequence_duration_seconds".to_string());
            fields.insert("sequence_duration".to_string());
            fields.insert("sequence_count".to_string());
        }
        Command::Spath { output, .. } => {
            if let Some(o) = output {
                fields.insert(o.to_lowercase());
            }
        }
        Command::Anomaly { .. } => {
            fields.insert("anomaly_score".to_string());
            fields.insert("is_anomaly".to_string());
        }
        Command::ResolveIdentity { .. } => {
            // Mirror the codegen registration (NAN-1380, regression of #2057):
            // `collect_computed_field_names` in `clickhouse_sql_gen::field_analysis`
            // registers the always-bare resolve_identity outputs plus the bare
            // `identity_*` attribute aliases. Without this arm the validator's
            // typo gate rejected 11 of the 13 bare aliases. Validation is
            // permissive by design, so the aliases are registered for every
            // resolve_identity (codegen only emits them when a single
            // resolve_identity makes them unambiguous — an ambiguous reference
            // is codegen's diagnostic to give, not a "did you mean" typo).
            for f in [
                "identity_confidence",
                "identity_observed_at",
                "identity_source",
                "identity_fqdn",
                "identity_ip",
            ] {
                fields.insert(f.to_string());
            }
            for (col_suffix, _, _) in
                crate::query::clickhouse_sql_gen::identity::IDENTITY_COLUMN_FIELDS.iter()
            {
                fields.insert((*col_suffix).to_string());
            }
            for (col_suffix, _, _) in
                crate::query::clickhouse_sql_gen::identity::IDENTITY_DICT_ONLY_FIELDS.iter()
            {
                fields.insert((*col_suffix).to_string());
            }
        }
        // Commands that don't create new field names
        _ => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::query::parse_query;

    #[test]
    fn test_stats_with_alias() {
        let query = parse_query("* | stats dc(user) as unique_users by src_ip").unwrap();
        let fields = collect_derived_fields(&query);
        assert!(fields.contains("unique_users"));
        assert!(fields.contains("src_ip"));
    }

    #[test]
    fn test_stats_default_names() {
        let query = parse_query("* | stats count() dc(user) by src_ip").unwrap();
        let fields = collect_derived_fields(&query);
        assert!(fields.contains("count"));
        assert!(fields.contains("dc"));
        assert!(fields.contains("src_ip"));
    }

    #[test]
    fn test_unaliased_agg_registers_func_field_reference_alias() {
        // NAN-1396 Bug A: codegen accepts `avg_bytes_in` as a downstream
        // reference to un-aliased `avg(bytes_in)` (NAN-1339 remap), so the
        // validator must register that name too — for exactly the command
        // arms the remap covers.
        for q in [
            "* | stats avg(bytes_in) by src_ip",
            "* | chart avg(bytes_in) by src_ip",
            "* | timechart span=1h avg(bytes_in)",
            "* | eventstats avg(bytes_in)",
        ] {
            let query = parse_query(q).unwrap_or_else(|e| panic!("parse {q}: {e}"));
            let fields = collect_derived_fields(&query);
            assert!(fields.contains("avg"), "{q}: missing output alias");
            assert!(
                fields.contains("avg_bytes_in"),
                "{q}: missing {{func}}_{{field}} reference alias"
            );
        }
    }

    #[test]
    fn test_streamstats_does_not_register_reference_alias() {
        // The codegen remap (`collect_agg_reference_aliases`) doesn't cover
        // streamstats — registering `avg_bytes_in` here would just unmask a
        // later codegen failure.
        let query = parse_query("* | streamstats avg(bytes_in)").unwrap();
        let fields = collect_derived_fields(&query);
        assert!(fields.contains("avg"));
        assert!(!fields.contains("avg_bytes_in"));
    }

    #[test]
    fn test_aliased_agg_does_not_register_reference_alias() {
        // The codegen remap only fires when `agg.alias.is_none()`.
        let query = parse_query("* | stats avg(bytes_in) as mean_bytes by src_ip").unwrap();
        let fields = collect_derived_fields(&query);
        assert!(fields.contains("mean_bytes"));
        assert!(!fields.contains("avg_bytes_in"));
    }

    /// NAN-1396 drift pin: for every `AggFunc` variant, validation's registered
    /// names for an un-aliased field-bearing aggregation must cover BOTH
    /// `output_alias()` and the `{func}_{field}` reference form — and the
    /// codegen remap (`collect_agg_reference_aliases`) must agree that the
    /// reference form resolves to `output_alias()`. The exhaustive match below
    /// forces a decision here if `AggFunc` gains a variant.
    #[test]
    fn test_agg_output_names_match_codegen_for_every_func() {
        use crate::query::ast::{Command, Query, SearchExpr};
        use crate::query::clickhouse_sql_gen::field_analysis::collect_agg_reference_aliases;

        let all_funcs = [
            AggFunc::Count,
            AggFunc::Dc,
            AggFunc::EstDc,
            AggFunc::Sum,
            AggFunc::Avg,
            AggFunc::Min,
            AggFunc::Max,
            AggFunc::Values,
            AggFunc::List,
            AggFunc::First,
            AggFunc::Last,
            AggFunc::Range,
            AggFunc::Earliest,
            AggFunc::Latest,
            AggFunc::Stdev,
            AggFunc::Var,
            AggFunc::Median,
            AggFunc::Perc95,
            AggFunc::Percentile(90),
            AggFunc::Mode,
            AggFunc::Sparkline,
            AggFunc::Rate,
            AggFunc::HistogramQuantile(95),
        ];
        // Exhaustiveness guard: a new AggFunc variant fails compilation here
        // until it's added to `all_funcs` above (and a naming decision made).
        for f in &all_funcs {
            match f {
                AggFunc::Count
                | AggFunc::Dc
                | AggFunc::EstDc
                | AggFunc::Sum
                | AggFunc::Avg
                | AggFunc::Min
                | AggFunc::Max
                | AggFunc::Values
                | AggFunc::List
                | AggFunc::First
                | AggFunc::Last
                | AggFunc::Range
                | AggFunc::Earliest
                | AggFunc::Latest
                | AggFunc::Stdev
                | AggFunc::Var
                | AggFunc::Median
                | AggFunc::Perc95
                | AggFunc::Percentile(_)
                | AggFunc::Mode
                | AggFunc::Sparkline
                | AggFunc::Rate
                | AggFunc::HistogramQuantile(_) => {}
            }
        }

        for func in all_funcs {
            let agg = Aggregation::new(func, Some("bytes_in".to_string()));
            let command = Command::Stats {
                aggregations: vec![agg.clone()],
                group_by: None,
            };
            let mut registered = HashSet::new();
            collect_command_output_fields(&command, &mut registered);

            let output_alias = agg.output_alias().to_lowercase();
            let reference = format!("{}_bytes_in", func.as_str()).to_lowercase();
            assert!(
                registered.contains(&output_alias),
                "{func:?}: validation missing output_alias '{output_alias}'"
            );
            assert!(
                registered.contains(&reference),
                "{func:?}: validation missing reference form '{reference}'"
            );

            // Codegen agreement: the reference form must resolve to the output
            // alias (or already BE the output alias, as for values/list).
            let query = Query::Piped {
                source: Box::new(Query::Search(SearchExpr::Keyword("*".to_string()))),
                command,
            };
            let remap = collect_agg_reference_aliases(&query, &HashSet::new());
            if reference == agg.output_alias() {
                assert!(
                    !remap.contains_key(&reference),
                    "{func:?}: remap should not contain identity mapping"
                );
            } else {
                assert_eq!(
                    remap.get(&format!("{}_bytes_in", func.as_str())),
                    Some(&agg.output_alias()),
                    "{func:?}: codegen remap disagrees with validation"
                );
            }
        }
    }

    #[test]
    fn test_lookup_multi_field_output_registered() {
        // NAN-1396 Bug B companion: every OUTPUT field is a derived field.
        let query =
            parse_query("* | lookup threats src_ip OUTPUT threat_type, confidence").unwrap();
        let fields = collect_derived_fields(&query);
        assert!(fields.contains("threat_type"));
        assert!(fields.contains("confidence"));
    }

    #[test]
    fn test_stats_values_default_name() {
        let query = parse_query("* | stats values(user) by src_ip").unwrap();
        let fields = collect_derived_fields(&query);
        assert!(fields.contains("values_user"));
    }

    #[test]
    fn test_eval_assignments() {
        let query =
            parse_query("* | eval total=bytes_in+bytes_out, ratio=bytes_in/bytes_out").unwrap();
        let fields = collect_derived_fields(&query);
        assert!(fields.contains("total"));
        assert!(fields.contains("ratio"));
    }

    #[test]
    fn test_rex_capture_groups() {
        let query =
            parse_query(r#"* | rex field=message "(?<username>\w+)@(?<domain>\w+\.\w+)""#).unwrap();
        let fields = collect_derived_fields(&query);
        assert!(fields.contains("username"));
        assert!(fields.contains("domain"));
    }

    #[test]
    fn test_multi_stage_pipeline() {
        // stats creates unique_users → where references it → table references it
        let query = parse_query("* | stats dc(user) as unique_users by src_ip | where unique_users > 5 | table src_ip, unique_users").unwrap();
        let fields = collect_derived_fields(&query);
        assert!(fields.contains("unique_users"));
        assert!(fields.contains("src_ip"));
    }

    #[test]
    fn test_risk_command_fields() {
        let query = parse_query("* | risk score=80").unwrap();
        let fields = collect_derived_fields(&query);
        assert!(fields.contains("risk_score"));
        assert!(fields.contains("risk_factors"));
        assert!(fields.contains("risk_level"));
    }

    #[test]
    fn test_bin_default_time_bucket() {
        let query = parse_query("* | bin span=1h").unwrap();
        let fields = collect_derived_fields(&query);
        assert!(fields.contains("time_bucket"));
    }

    #[test]
    fn test_bin_with_alias() {
        let query = parse_query("* | bin span=1h as hourly_bucket").unwrap();
        let fields = collect_derived_fields(&query);
        assert!(fields.contains("hourly_bucket"));
    }

    #[test]
    fn test_rename_creates_new_field() {
        let query = parse_query("* | rename src_ip as source_address").unwrap();
        let fields = collect_derived_fields(&query);
        assert!(fields.contains("source_address"));
    }

    #[test]
    fn test_simple_search_no_derived_fields() {
        let query = parse_query("src_ip=192.168.1.1").unwrap();
        let fields = collect_derived_fields(&query);
        assert!(fields.is_empty());
    }

    #[test]
    fn test_transaction_derived_fields() {
        let query = parse_query("* | transaction user").unwrap();
        let fields = collect_derived_fields(&query);
        assert!(fields.contains("user"));
        assert!(fields.contains("duration"));
        assert!(fields.contains("eventcount"));
    }

    #[test]
    fn test_timechart_derived_fields() {
        let query = parse_query("* | timechart span=1h count()").unwrap();
        let fields = collect_derived_fields(&query);
        assert!(fields.contains("time_bucket"));
        assert!(fields.contains("count"));
    }

    #[test]
    fn test_top_derived_fields() {
        let query = parse_query("* | top src_ip").unwrap();
        let fields = collect_derived_fields(&query);
        assert!(fields.contains("src_ip"));
        assert!(fields.contains("count"));
        assert!(fields.contains("percent"));
    }

    #[test]
    fn test_resolve_identity_derived_fields() {
        // NAN-1380 (G8): the bare identity_* aliases registered for codegen in
        // field_analysis::collect_computed_field_names must also be derived
        // fields here, or downstream references are rejected as typos.
        let query = parse_query("* | resolve_identity").unwrap();
        let fields = collect_derived_fields(&query);
        for f in [
            "identity_confidence",
            "identity_observed_at",
            "identity_source",
            "identity_fqdn",
            "identity_ip",
        ] {
            assert!(fields.contains(f), "missing always-bare output: {f}");
        }
        for (col_suffix, _, _) in
            crate::query::clickhouse_sql_gen::identity::IDENTITY_COLUMN_FIELDS
                .iter()
                .chain(crate::query::clickhouse_sql_gen::identity::IDENTITY_DICT_ONLY_FIELDS.iter())
        {
            assert!(fields.contains(*col_suffix), "missing bare alias: {col_suffix}");
        }
    }

    #[test]
    #[ignore = "sequence syntax has changed; update derived-field expectations before re-enabling"]
    fn test_sequence_derived_fields() {
        let query = parse_query(
            r#"* | sequence by src_ip [action="login_failed"] [action="login_success"] maxspan=5m"#,
        )
        .unwrap();
        let fields = collect_derived_fields(&query);
        assert!(fields.contains("src_ip"));
        assert!(fields.contains("sequence_duration_seconds"));
        // Auto-captured condition fields get step prefixes
        assert!(fields.contains("step1_action"));
        assert!(fields.contains("step2_action"));
        assert!(fields.contains("step1_time"));
        assert!(fields.contains("step2_time"));
    }

    #[test]
    #[ignore = "sequence syntax has changed; update derived-field expectations before re-enabling"]
    fn test_sequence_capture_fields_derived() {
        let query = parse_query(r#"* | sequence by user, src_ip fields(user_agent, enriched_src_country) [action="login" status="failure"] [action="login" status="failure"] [action="login" status="success"] maxspan=5m"#).unwrap();
        let fields = collect_derived_fields(&query);
        assert!(fields.contains("user"));
        assert!(fields.contains("src_ip"));
        // capture_fields get step-prefixed for each condition
        assert!(fields.contains("step1_user_agent"));
        assert!(fields.contains("step3_enriched_src_country"));
        assert!(fields.contains("step3_user_agent"));
        assert!(fields.contains("sequence_duration_seconds"));
        assert!(fields.contains("sequence_count"));
    }
}
