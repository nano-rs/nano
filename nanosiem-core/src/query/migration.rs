// SPDX-License-Identifier: AGPL-3.0-or-later

//! Versioned, one-time saved-content migration into the canonical OCSF lane.
//!
//! This is deliberately separate from [`crate::schema::SchemaProfile`]. The
//! forward lake runtime rejects legacy field names; it never calls this code.
//! A cutover tool parses old nPL, rewrites only AST positions that are field
//! references, and then asks the strict OCSF compiler to validate the result.

use std::collections::{BTreeMap, BTreeSet};

use serde::Serialize;

use super::{Aggregation, Command, EvalExpression, Query, RiskScoreExpr, SearchExpr, UrlTemplate};

pub const OCSF_CONTENT_MIGRATION_CONTRACT: &str = "ocsf-1.9";

/// A deterministic proposal. `manual_reasons` is fail-closed: the database
/// migrator must not apply a proposal carrying any entry even if it compiles.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct OcsfContentMigration {
    pub target_contract: &'static str,
    pub replacements: BTreeMap<String, String>,
    pub manual_reasons: Vec<String>,
}

#[derive(Default)]
struct MigrationState {
    derived_fields: BTreeSet<String>,
    replacements: BTreeMap<String, String>,
    manual_reasons: BTreeSet<String>,
}

/// Rewrite a parsed legacy query in place. Values, regexes, lookup-table
/// columns, aliases, and generated field names are not treated as event fields.
pub fn migrate_query_to_ocsf_1_9(query: &mut Query) -> OcsfContentMigration {
    let mut state = MigrationState::default();
    migrate_query(query, &mut state);
    OcsfContentMigration {
        target_contract: OCSF_CONTENT_MIGRATION_CONTRACT,
        replacements: state.replacements,
        manual_reasons: state.manual_reasons.into_iter().collect(),
    }
}

/// Exact, versioned migration knowledge. This is not a runtime alias table.
/// Class-dependent concepts choose the path used by Nano's existing content;
/// the strict compiler still blocks a proposal if that path is not part of the
/// tenant's signed OCSF table contract.
pub fn legacy_field_target(field: &str) -> Option<&'static str> {
    Some(match field.to_ascii_lowercase().as_str() {
        "id" => "metadata.uid",
        "timestamp" | "time_dt" | "_time" => "time",
        "source_type" | "sourcetype" => "metadata.log_source",
        "event_bytes" => "raw_data_size",
        "_raw" => "raw_data",
        "ext" => "unmapped",
        "tags" => "unmapped.tags",
        "bytes" => "traffic.bytes",
        "response_time" => "duration",
        "protocol" => "connection_info.protocol_name",
        "activity" | "action" | "event_type" | "file_action" => "activity_name",
        "category" => "category_name",
        "src_ip" => "src_endpoint.ip",
        "dest_ip" | "dst_ip" => "dst_endpoint.ip",
        "src_port" => "src_endpoint.port",
        "dest_port" | "dst_port" => "dst_endpoint.port",
        "src_host" => "src_endpoint.hostname",
        "dest_host" | "dst_host" => "dst_endpoint.hostname",
        "src_mac" => "src_endpoint.mac",
        "dest_mac" | "dst_mac" => "dst_endpoint.mac",
        "user" | "src_user" | "dest_user" | "username" | "target_user" => "user.name",
        "display_name" => "user.display_name",
        "email" => "user.email_addr",
        "process_name" => "process.name",
        "process_id" => "process.pid",
        "process_guid" => "process.uid",
        "command_line" => "process.cmd_line",
        "process_path" => "process.file.path",
        "process_hash" => "process.file.hashes.value",
        // In OCSF Process Activity, the process being created/acted on is
        // `process`; its initiating parent is `actor.process`. OCSF does not
        // model that actor as `actor.process.parent_process`.
        "parent_process_name" => "actor.process.name",
        "parent_process_id" => "actor.process.pid",
        "parent_process_guid" => "actor.process.uid",
        "url" => "http_request.url.url_string",
        "url_domain" => "http_request.url.hostname",
        "uri_path" => "http_request.url.path",
        "http_referrer" => "http_request.referrer",
        "file_path" => "file.path",
        "file_name" => "file.name",
        "file_hash" => "file.hashes.value",
        "bytes_in" => "traffic.bytes_in",
        "bytes_out" => "traffic.bytes_out",
        "session_id" => "session.uid",
        "http_method" => "http_request.http_method",
        // The legacy docs/content corpus uses `status` exclusively as the
        // numeric HTTP response code. Canonical OCSF's bare `status` is a
        // String lifecycle label, so retaining the legacy spelling would turn
        // predicates such as `status >= 500` into invalid typed comparisons.
        // This is a one-time legacy-content rewrite, not a runtime alias.
        "status" => "http_response.code",
        "auth_result" => "status",
        "auth_type" | "authentication_method" => "auth_protocol",
        "http_status_code" => "http_response.code",
        "http_user_agent" => "http_request.user_agent",
        "cloud_provider" => "cloud.provider",
        "cloud_region" => "cloud.region",
        "cloud_account_id" => "cloud.account.uid",
        "cloud_account_name" => "cloud.account.name",
        "cloud_service" => "api.service.name",
        "resource_id" => "resources.uid",
        "resource_name" => "resources.name",
        "resource_type" => "resources.type",
        // These producer-specific fields have no OCSF 1.9 dictionary mapping.
        // They already live under the canonical `unmapped` object in the writer.
        "error_code" => "unmapped.error_code",
        "error_message" => "unmapped.error_message",
        "threat_tier" => "unmapped.threat_tier",
        "threat_score" => "unmapped.threat_score",
        "threat_blocked" => "unmapped.threat_blocked",
        _ => return None,
    })
}

fn migrate_query(query: &mut Query, state: &mut MigrationState) {
    match query {
        Query::Search(expression) => migrate_search_expr(expression, state),
        Query::Piped { source, command } => {
            migrate_query(source, state);
            migrate_command(command, state);
        }
    }
}

fn migrate_field(field: &mut String, state: &mut MigrationState) -> bool {
    let lower = field.to_ascii_lowercase();
    if state.derived_fields.contains(&lower) || lower.starts_with("unmapped.") {
        return false;
    }
    let Some(target) = legacy_field_target(&lower) else {
        return false;
    };
    let original = field.clone();
    *field = target.to_string();
    state.replacements.insert(original, target.to_string());
    true
}

fn migrate_fields(fields: &mut [String], state: &mut MigrationState) {
    for field in fields {
        migrate_field(field, state);
    }
}

/// Migrate the field inside anomaly's aggregation-first spelling, e.g.
/// `sum(bytes)` -> `sum(traffic.bytes)`. The anomaly parser intentionally
/// stores that expression as one string rather than an [`Aggregation`], so a
/// plain `migrate_field` can never see the inner event field.
fn migrate_anomaly_field(field: &mut String, state: &mut MigrationState) {
    let Some(open) = field.find('(') else {
        migrate_field(field, state);
        return;
    };
    let Some(close) = field.rfind(')') else {
        migrate_field(field, state);
        return;
    };
    if close <= open {
        migrate_field(field, state);
        return;
    }
    let mut inner = field[open + 1..close].trim().to_string();
    if inner.is_empty() || inner == "*" || inner.contains(',') {
        return;
    }
    if migrate_field(&mut inner, state) {
        *field = format!("{}({}){}", &field[..open], inner, &field[close + 1..]);
    }
}

fn migrate_search_expr(expression: &mut SearchExpr, state: &mut MigrationState) {
    match expression {
        SearchExpr::Keyword(_)
        | SearchExpr::LiteralComparison { .. }
        | SearchExpr::IocMatch { .. } => {}
        SearchExpr::FieldFilter { field, .. }
        | SearchExpr::FieldFunctionFilter { field, .. }
        | SearchExpr::InList { field, .. } => {
            migrate_field(field, state);
            if let SearchExpr::FieldFunctionFilter { function, .. } = expression {
                migrate_eval(function, state);
            }
        }
        SearchExpr::FunctionFilter { function, .. }
        | SearchExpr::BooleanFunction(function)
        | SearchExpr::EvalPredicate(function) => migrate_eval(function, state),
        SearchExpr::And(left, right) | SearchExpr::Or(left, right) => {
            migrate_search_expr(left, state);
            migrate_search_expr(right, state);
        }
        SearchExpr::Not(inner) | SearchExpr::Group(inner) => migrate_search_expr(inner, state),
        SearchExpr::InSubsearch {
            field, subsearch, ..
        } => {
            migrate_field(field, state);
            migrate_query(subsearch, &mut MigrationState::default());
        }
    }
}

fn migrate_eval(expression: &mut EvalExpression, state: &mut MigrationState) {
    match expression {
        EvalExpression::Field(field) => {
            migrate_field(field, state);
        }
        EvalExpression::Literal(_) => {}
        EvalExpression::BinaryOp { left, right, .. } => {
            migrate_eval(left, state);
            migrate_eval(right, state);
        }
        EvalExpression::FunctionCall { args, .. } => {
            for argument in args {
                migrate_eval(argument, state);
            }
        }
    }
}

fn migrate_aggregation(aggregation: &mut Aggregation, state: &mut MigrationState) {
    let original_output = aggregation.output_alias();
    if let Some(field) = &mut aggregation.field {
        migrate_field(field, state);
    }
    if let Some(condition) = &mut aggregation.condition {
        migrate_eval(condition, state);
    }
    if let Some(expression) = &mut aggregation.field_expr {
        migrate_eval(expression, state);
    }
    if aggregation.alias.is_none() && aggregation.output_alias() != original_output {
        // Preserve a generated pipeline-column name so downstream references
        // do not silently change when the input event field becomes dotted.
        aggregation.alias = Some(original_output);
    }
}

fn aggregation_outputs(aggregations: &[Aggregation]) -> BTreeSet<String> {
    aggregations
        .iter()
        .map(|aggregation| aggregation.output_alias().to_ascii_lowercase())
        .collect()
}

fn add_fields(target: &mut BTreeSet<String>, fields: &[String]) {
    target.extend(fields.iter().map(|field| field.to_ascii_lowercase()));
}

fn migrate_command(command: &mut Command, state: &mut MigrationState) {
    match command {
        Command::Stats {
            aggregations,
            group_by,
        }
        | Command::Chart {
            aggregations,
            group_by,
        } => {
            for aggregation in aggregations.iter_mut() {
                migrate_aggregation(aggregation, state);
            }
            if let Some(fields) = group_by {
                migrate_fields(fields, state);
            }
            let mut outputs = aggregation_outputs(aggregations);
            if let Some(fields) = group_by {
                add_fields(&mut outputs, fields);
            }
            state.derived_fields = outputs;
        }
        Command::StreamStats {
            aggregations,
            group_by,
            ..
        }
        | Command::EventStats {
            aggregations,
            group_by,
        } => {
            for aggregation in aggregations.iter_mut() {
                migrate_aggregation(aggregation, state);
            }
            if let Some(fields) = group_by {
                migrate_fields(fields, state);
                add_fields(&mut state.derived_fields, fields);
            }
            state
                .derived_fields
                .extend(aggregation_outputs(aggregations));
        }
        Command::Where { condition } => migrate_search_expr(condition, state),
        Command::Sort { fields, .. } => {
            for field in fields {
                migrate_field(&mut field.field, state);
            }
        }
        Command::Head { .. }
        | Command::Tail { .. }
        | Command::Format { .. }
        | Command::Sample { .. }
        | Command::Reverse
        | Command::Ai { .. }
        | Command::Output { .. }
        | Command::Services
        | Command::Service { .. }
        | Command::Trace { .. }
        | Command::Metric { .. }
        | Command::Retro { .. }
        | Command::Cloud { .. } => {}
        Command::Prevalence {
            artifact_fields, ..
        } => migrate_fields(artifact_fields, state),
        Command::Timechart {
            aggregations,
            split_by,
            ..
        } => {
            for aggregation in aggregations.iter_mut() {
                migrate_aggregation(aggregation, state);
            }
            migrate_fields(split_by, state);
            let mut outputs = aggregation_outputs(aggregations);
            add_fields(&mut outputs, split_by);
            outputs.insert("time".to_string());
            state.derived_fields = outputs;
        }
        Command::Table { fields } => {
            let mut outputs = BTreeSet::new();
            for field in fields {
                migrate_field(&mut field.name, state);
                outputs.insert(
                    field
                        .alias
                        .as_deref()
                        .unwrap_or(&field.name)
                        .to_ascii_lowercase(),
                );
            }
            state.derived_fields = outputs;
        }
        Command::Rename { mappings } => {
            for mapping in mappings {
                migrate_field(&mut mapping.from, state);
                state.derived_fields.insert(mapping.to.to_ascii_lowercase());
            }
        }
        Command::Lookup {
            event_field,
            output_fields,
            output_renames,
            ..
        } => {
            migrate_field(event_field, state);
            if let Some(fields) = output_fields {
                for field in fields {
                    let target = output_renames
                        .iter()
                        .find(|r| &r.from == field)
                        .map_or(&*field, |r| &r.to);
                    state.derived_fields.insert(target.to_ascii_lowercase());
                }
            }
        }
        Command::Eval { assignments } => {
            for assignment in assignments {
                migrate_eval(&mut assignment.expression, state);
                state
                    .derived_fields
                    .insert(assignment.field.to_ascii_lowercase());
            }
        }
        Command::Dedup { fields, .. }
        | Command::Fields { fields, .. }
        | Command::Return { fields, .. } => migrate_fields(fields, state),
        Command::Bin { field, alias, .. } => {
            if let Some(field) = field {
                migrate_field(field, state);
            }
            if let Some(alias) = alias {
                state.derived_fields.insert(alias.to_ascii_lowercase());
            }
        }
        Command::Rex { field, pattern, .. } => {
            if let Some(field) = field {
                migrate_field(field, state);
            }
            for capture in named_regex_captures(pattern) {
                if legacy_field_target(&capture).is_some() {
                    state.manual_reasons.insert(format!(
                        "regex capture {capture:?} is a generated field whose downstream migration needs semantic review"
                    ));
                }
                state.derived_fields.insert(capture.to_ascii_lowercase());
            }
        }
        Command::Top {
            field, by_fields, ..
        }
        | Command::Rare {
            field, by_fields, ..
        } => {
            migrate_field(field, state);
            migrate_fields(by_fields, state);
            let mut outputs = BTreeSet::from([field.to_ascii_lowercase()]);
            add_fields(&mut outputs, by_fields);
            outputs.extend(["count".to_string(), "percent".to_string()]);
            state.derived_fields = outputs;
        }
        Command::Transaction {
            fields,
            startswith,
            endswith,
            ..
        } => {
            migrate_fields(fields, state);
            if let Some(expression) = startswith {
                migrate_search_expr(expression, state);
            }
            if let Some(expression) = endswith {
                migrate_search_expr(expression, state);
            }
            let mut outputs = BTreeSet::new();
            add_fields(&mut outputs, fields);
            outputs.extend(["duration".to_string(), "eventcount".to_string()]);
            state.derived_fields = outputs;
        }
        Command::Fillnull { fields, .. } => {
            if let Some(fields) = fields {
                migrate_fields(fields, state);
            }
        }
        Command::Mvexpand { field, .. } => {
            migrate_field(field, state);
        }
        Command::Spath { input, output, .. } => {
            if let Some(input) = input {
                migrate_field(input, state);
            }
            if let Some(output) = output {
                state.derived_fields.insert(output.to_ascii_lowercase());
            }
        }
        Command::Append { subsearch, .. } => {
            migrate_query(subsearch, &mut MigrationState::default());
        }
        Command::Join {
            fields, subsearch, ..
        } => {
            migrate_fields(fields, state);
            migrate_query(subsearch, &mut MigrationState::default());
        }
        Command::Risk {
            score,
            entity_field,
            factor,
            ..
        } => {
            if let RiskScoreExpr::Dynamic(expression) = score {
                migrate_eval(expression, state);
            }
            if let Some(field) = entity_field {
                migrate_field(field, state);
            }
            if let Some(expression) = factor {
                migrate_eval(expression, state);
            }
            state.derived_fields.extend([
                "risk_score".to_string(),
                "risk_entity".to_string(),
                "risk_factors".to_string(),
            ]);
        }
        Command::Sequence {
            group_by,
            conditions,
            capture_fields,
            ..
        } => {
            migrate_fields(group_by, state);
            for condition in conditions {
                migrate_search_expr(condition, state);
            }
            let changed_capture = capture_fields
                .iter_mut()
                .any(|field| migrate_field(field, state));
            if changed_capture {
                state.manual_reasons.insert(
                    "sequence capture fields changed; generated stepN_* output names must be migrated with the rule"
                        .to_string(),
                );
            }
        }
        Command::Funnel {
            group_by, steps, ..
        } => {
            migrate_fields(group_by, state);
            for (_, expression) in steps {
                migrate_search_expr(expression, state);
            }
        }
        Command::Anomaly {
            field, by_fields, ..
        } => {
            migrate_anomaly_field(field, state);
            migrate_fields(by_fields, state);
        }
        Command::InputLookup { url, key_field, .. } => {
            if let Some(field) = key_field {
                migrate_field(field, state);
            }
            let mut template = url.template.clone();
            for field in url.fields.clone() {
                let mut migrated = field.clone();
                if migrate_field(&mut migrated, state) {
                    template =
                        template.replace(&format!("{{{field}}}"), &format!("{{{migrated}}}"));
                }
            }
            *url = UrlTemplate::new(&template);
        }
        Command::Tree {
            parent_field,
            child_field,
            label_field,
            detail_field,
            prevalence_field,
            ..
        } => {
            migrate_field(parent_field, state);
            migrate_field(child_field, state);
            migrate_field(label_field, state);
            if let Some(field) = detail_field {
                migrate_field(field, state);
            }
            if let Some(field) = prevalence_field {
                migrate_field(field, state);
            }
        }
        Command::ResolveIdentity { field, .. } => {
            migrate_field(field, state);
        }
        Command::Asset {
            identifier_field, ..
        } => {
            if let Some(field) = identifier_field {
                migrate_field(field, state);
            }
        }
        Command::Lateral { entity_field, .. } => {
            if let Some(field) = entity_field {
                migrate_field(field, state);
            }
        }
        Command::Baseline { dims, .. } => {
            if let Some(fields) = dims {
                migrate_fields(fields, state);
            }
        }
    }
}

fn named_regex_captures(pattern: &str) -> Vec<String> {
    // Both `(?<name>...)` and Python-style `(?P<name>...)` are accepted by the
    // nPL rex parser/SQL generator. Keep the migration's generated-field
    // tracking in lock-step so a downstream `table name` never rewrites the
    // capture as though it were a legacy physical event field.
    let Ok(regex) = regex::Regex::new(r"\(\?P?<([A-Za-z_][A-Za-z0-9_]*)>") else {
        return Vec::new();
    };
    regex
        .captures_iter(pattern)
        .filter_map(|capture| capture.get(1).map(|name| name.as_str().to_string()))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::query::{parse_query, PrettyPrint};

    fn migrate(query: &str) -> (String, OcsfContentMigration) {
        let mut parsed = parse_query(query).expect("query parses");
        let report = migrate_query_to_ocsf_1_9(&mut parsed);
        (parsed.pretty_print(), report)
    }

    #[test]
    fn rewrites_only_field_positions_not_values_or_regexes() {
        let (query, report) = migrate(
            r#"source_type="src_ip" command_line=/src_ip.*source_type/i | table timestamp, src_ip"#,
        );
        assert!(query.contains(r#"metadata.log_source="src_ip""#));
        assert!(query.contains("process.cmd_line="));
        assert!(query.contains("src_ip.*source_type"));
        assert!(!query.contains("src_endpoint.ip.*metadata.log_source"));
        assert!(query.contains("table time, src_endpoint.ip"));
        assert!(report.manual_reasons.is_empty());
    }

    #[test]
    fn preserves_generated_aggregation_aliases() {
        let (query, _) = migrate(
            "source_type=firewall | stats values(src_ip) by user | table user, values_src_ip",
        );
        assert_eq!(
            query,
            // NAN-2380: a bare RHS is re-emitted bare, so the migrated text
            // keeps the spelling the analyst wrote (and its Bareword marker).
            "metadata.log_source=firewall | stats values(src_endpoint.ip) as values_src_ip by user.name | table user.name, values_src_ip"
        );
    }

    #[test]
    fn rewrites_generic_docs_fields_to_real_ocsf_paths() {
        let (query, report) = migrate(
            "* | stats sum(bytes) as transferred, avg(response_time) as latency by protocol | fields - ext | mvexpand tags | table _time, _raw, transferred, latency, connection_info.protocol_name",
        );
        assert_eq!(
            query,
            "* | stats sum(traffic.bytes) as transferred, avg(duration) as latency by connection_info.protocol_name | fields - unmapped | mvexpand unmapped.tags | table time, raw_data, transferred, latency, connection_info.protocol_name"
        );
        assert!(report.manual_reasons.is_empty());
    }

    #[test]
    fn rewrites_field_inside_anomaly_aggregation_expression() {
        let (query, report) = migrate("* | anomaly sum(bytes) by src_ip");
        assert_eq!(
            query,
            "* | anomaly sum(traffic.bytes) by src_endpoint.ip threshold=3"
        );
        assert_eq!(
            report.replacements,
            BTreeMap::from([
                ("bytes".to_string(), "traffic.bytes".to_string()),
                ("src_ip".to_string(), "src_endpoint.ip".to_string()),
            ])
        );
    }

    #[test]
    fn rewrites_process_tree_to_ocsf_actor_process_relationship() {
        let (query, report) = migrate(
            "* | tree parent=parent_process_guid child=process_guid label=process_name detail=command_line",
        );
        assert_eq!(
            query,
            "* | tree parent=actor.process.uid child=process.uid label=process.name detail=process.cmd_line"
        );
        assert_eq!(
            report
                .replacements
                .get("parent_process_guid")
                .map(String::as_str),
            Some("actor.process.uid")
        );
    }

    #[test]
    fn rewrites_legacy_numeric_http_status_without_touching_auth_status_targets() {
        let (query, report) = migrate("status>=500 | stats count by status | table status, count");
        assert_eq!(
            query,
            "http_response.code>=500 | stats count() by http_response.code | table http_response.code, count"
        );
        assert!(report.manual_reasons.is_empty());

        let (auth_query, _) = migrate("auth_result=Failure | table auth_result");
        assert_eq!(auth_query, "status=Failure | table status");
    }

    #[test]
    fn python_style_rex_capture_is_a_derived_field_downstream() {
        let (query, report) =
            migrate(r#"* | rex field=message "pid=(?P<user>[0-9]+)" | table user, src_ip"#);
        assert!(query.contains("table user, src_endpoint.ip"), "{query}");
        assert_eq!(report.manual_reasons.len(), 1);
        assert!(report.manual_reasons[0].contains("generated field"));
    }

    #[test]
    fn lookup_table_columns_are_not_event_field_mappings() {
        let (query, _) = migrate(
            "src_ip=* | lookup assets src_ip AS ip OUTPUT source_type | table src_ip, source_type",
        );
        assert_eq!(
            query,
            "src_endpoint.ip=\"*\" | lookup assets ip AS src_endpoint.ip OUTPUT source_type | table src_endpoint.ip, source_type"
        );
    }

    #[test]
    fn inputlookup_rewrites_typed_placeholders() {
        let (query, _) =
            migrate("src_ip=* | inputlookup url=\"https://example.invalid/{src_ip}\" key=src_ip");
        assert!(query.contains("{src_endpoint.ip}"));
        assert!(query.contains("key=src_endpoint.ip"));
    }

    #[test]
    fn sequence_capture_changes_fail_closed_for_manual_migration() {
        let (_, report) = migrate(
            "source_type=\"sysmon\" | sequence by user maxspan=5m fields(src_host) [process_name=\"cmd\"]",
        );
        assert_eq!(report.manual_reasons.len(), 1);
    }

    #[test]
    fn migration_is_idempotent() {
        let (first, _) = migrate("source_type=firewall src_ip=10.0.0.1 | table timestamp, src_ip");
        let (second, report) = migrate(&first);
        assert_eq!(first, second);
        assert!(report.replacements.is_empty());
    }
}
