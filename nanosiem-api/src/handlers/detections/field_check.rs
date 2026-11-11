// SPDX-License-Identifier: AGPL-3.0-or-later

//! Field-name checks for `POST /api/rules/validate` (the detection editor's
//! inline validator).
//!
//! NAN-5275: the check is schema- and dataset-aware. A rule's query is
//! validated against the schema it actually runs on:
//! * `dataset=logs` on a UDM tenant: the UDM columns, as before;
//! * `dataset=logs` on an OCSF tenant: the OCSF promoted columns plus the
//!   profile's alias layer (`SchemaProfile::is_queryable_field`);
//! * `dataset=risk|spans|metrics`: that dataset's own field universe (the
//!   seeded risk-notable rule queries `score_24h`, which is not a log field).
//!
//! Suggestions come from the same universe, so an OCSF tenant is never told to
//! use `src_ip` / `src_host`, and a risk rule is pointed at risk columns.

use std::collections::HashSet;
use std::sync::OnceLock;

use nanosiem_core::query::{suggest_similar_fields_in, Dataset};
use nanosiem_core::schema::{profile_for_id, SchemaId, SchemaProfile};
use nanosiem_core::udm::UdmField;

/// Direct ClickHouse columns of the UDM `logs` table (fast, indexed queries).
static UDM_CLICKHOUSE_COLUMNS: &[&str] = &[
    "_inserted_at",
    "answer",
    "auth_result",
    "auth_type",
    "authentication_method",
    "bytes_in",
    "bytes_out",
    "category",
    "change_type",
    "cloud_account_id",
    "cloud_account_name",
    "cloud_provider",
    "cloud_region",
    "cloud_service",
    "cve",
    "dest_host",
    "dest_ip",
    "dest_mac",
    "dest_port",
    "dest_user",
    "direction",
    "dns_answers",
    "duration",
    "dvc",
    "dvc_ip",
    "dvc_mac",
    "enrich_time",
    "event_type",
    "ext",
    "file_action",
    "file_hash",
    "file_name",
    "file_path",
    "file_size",
    "http_content_type",
    "http_method",
    "http_referrer",
    "http_user_agent",
    "id",
    "ingest_time",
    "message",
    "message_id",
    "metadata",
    "mfa_used",
    "mitre_technique_id",
    "namespace",
    "packets_in",
    "packets_out",
    "command_line",
    "parent_command_line",
    "parent_process_guid",
    "parent_process_id",
    "parent_process_path",
    "process_guid",
    "process_hash",
    "process_id",
    "process_name",
    "process_path",
    "protocol",
    "query",
    "query_type",
    "recipient",
    "recipient_domain",
    "record_type",
    "registry_key_name",
    "registry_path",
    "registry_value_data",
    "registry_value_name",
    "resource_id",
    "resource_name",
    "resource_type",
    "response_time",
    "result",
    "risk_entity",
    "risk_factors",
    "risk_level",
    "risk_score",
    "rule_id",
    "rule_name",
    "sender",
    "sender_domain",
    "session_id",
    "severity",
    "signature",
    "signature_id",
    "source",
    "source_type",
    "src_host",
    "src_ip",
    "src_mac",
    "src_port",
    "src_user",
    "status",
    "status_code",
    "subject",
    "timestamp",
    "uri_path",
    "url",
    "url_domain",
    "user",
    "user_agent",
    "user_domain",
    "user_id",
    "user_name",
    "user_type",
    "vendor_product",
    "vlan",
];

/// Operators and literals the field regex can capture.
const KEYWORDS: &[&str] = &[
    "and",
    "or",
    "not",
    "in",
    "like",
    "contains",
    "startswith",
    "endswith",
    "matches",
    "true",
    "false",
];

/// Command parameters (not schema fields).
const COMMAND_PARAMS: &[&str] = &[
    "enrich",
    "window",
    "current",
    "span",
    "limit",
    "as",
    "field",
    "mode",
    "score",
    "entity",
    "factor",
    "weight",
    "maxspan",
    "maxevents",
    "keeplast",
    "case_insensitive",
    "threshold",
    "method",
    "hop",
    "parent",
    "child",
    "label",
    "detail",
    "prevalence",
    "process",
    "web",
    "root",
    "max_age",
    "by",
    "value",
    "count",
    "output",
];

/// Fields added by `| prevalence enrich=true` (any schema).
const PREVALENCE_FIELDS: &[&str] = &[
    "hash_prevalence",
    "domain_prevalence",
    "hash_first_seen",
    "domain_first_seen",
    "host_count",
    "is_rare",
    "total_occurrences",
    "first_seen",
    "last_seen",
];

/// How many suggestions an unknown-field error carries.
const MAX_SUGGESTIONS: usize = 4;

/// Resolve the request's `dataset`. `None` / empty → logs (the rule default).
/// An unrecognised value is an error, not a silent logs fallback: the rule
/// save path rejects it too (`VALID_DATASETS`).
pub(crate) fn parse_dataset(raw: Option<&str>) -> Result<Dataset, String> {
    match raw.map(str::trim).filter(|s| !s.is_empty()) {
        None => Ok(Dataset::Logs),
        Some(s) => Dataset::from_selector_strict(s).ok_or_else(|| {
            format!("Unknown dataset '{s}'. Expected one of: logs, spans, metrics, risk")
        }),
    }
}

/// Selector name used in messages (`dataset=risk`).
fn dataset_name(dataset: Dataset) -> &'static str {
    match dataset {
        Dataset::Logs => "logs",
        Dataset::Spans => "spans",
        Dataset::Metrics => "metrics",
        Dataset::Risk => "risk",
    }
}

/// Field-like tokens the query compares (`name =`, `name >`, `name !=`, …).
/// Dotted OCSF paths (`src_endpoint.ip`) are captured whole; capturing only
/// the last segment (`ip`) used to raise a false "Unknown field" on OCSF.
pub(crate) fn referenced_fields(clean_query: &str) -> Vec<String> {
    static FIELD_RE: OnceLock<regex::Regex> = OnceLock::new();
    let re = FIELD_RE.get_or_init(|| {
        regex::Regex::new(r#"([a-zA-Z_][a-zA-Z0-9_]*(?:\.[a-zA-Z_][a-zA-Z0-9_]*)*)\s*[=!<>]"#)
            .unwrap()
    });
    let masked = mask_string_literals(clean_query);
    let mut out: Vec<String> = Vec::new();
    for cap in re.captures_iter(&masked) {
        if let Some(m) = cap.get(1) {
            let name = m.as_str().to_string();
            if !out.contains(&name) {
                out.push(name);
            }
        }
    }
    out
}

/// Blank out the contents of quoted string literals (`"…"`, `'…'`, with
/// backslash escapes) so a value such as `"/LogFile="` or `"key=clear"` is not
/// mistaken for a field comparison. Byte length is preserved.
fn mask_string_literals(query: &str) -> String {
    let mut out = String::with_capacity(query.len());
    let mut quote: Option<char> = None;
    let mut escaped = false;
    for c in query.chars() {
        match quote {
            Some(q) => {
                if escaped {
                    escaped = false;
                } else if c == '\\' {
                    escaped = true;
                } else if c == q {
                    quote = None;
                    out.push(c);
                    continue;
                }
                for _ in 0..c.len_utf8() {
                    out.push(' ');
                }
            }
            None => {
                if c == '"' || c == '\'' {
                    quote = Some(c);
                }
                out.push(c);
            }
        }
    }
    out
}

/// The schema a query on `dataset` reads: the tenant log profile for logs,
/// the per-query dataset profile otherwise (as `with_dataset` swaps in).
fn dataset_profile(
    dataset: Dataset,
    tenant: &std::sync::Arc<dyn SchemaProfile>,
) -> std::sync::Arc<dyn SchemaProfile> {
    match dataset {
        Dataset::Logs => std::sync::Arc::clone(tenant),
        Dataset::Spans => profile_for_id(SchemaId::Spans),
        Dataset::Metrics => profile_for_id(SchemaId::Metrics),
        Dataset::Risk => profile_for_id(SchemaId::Risk),
    }
}

/// UDM tenant, logs dataset — the pre-NAN-5275 rules, unchanged.
fn is_known_udm_log_field(field_name: &str, lower: &str, profile: &dyn SchemaProfile) -> bool {
    if UDM_CLICKHOUSE_COLUMNS.contains(&lower) {
        return true;
    }
    if lower.starts_with("ext.") {
        // The UDM JSON spill, addressed explicitly.
        return true;
    }
    if field_name.parse::<UdmField>().is_ok() {
        return true;
    }
    profile.is_known_field(field_name) || profile.is_known_field(lower)
}

/// Pipeline-added enrichment columns, valid on any log schema.
fn is_enrichment_field(lower: &str) -> bool {
    lower.starts_with("enriched_")
        || lower.starts_with("ioc_")
        || lower.starts_with("custom_")
        || lower.starts_with("prevalence_")
        || PREVALENCE_FIELDS.contains(&lower)
}

/// Whether `field_name` is readable by a query on `dataset` under `profile`.
fn is_known(field_name: &str, dataset: Dataset, profile: &dyn SchemaProfile) -> bool {
    let lower = field_name.to_lowercase();
    match dataset {
        Dataset::Logs => {
            if is_enrichment_field(&lower) {
                return true;
            }
            if profile.id() == SchemaId::Udm {
                is_known_udm_log_field(field_name, &lower, profile)
            } else {
                profile.is_queryable_field(field_name) || profile.is_queryable_field(&lower)
            }
        }
        // Derived / OTLP datasets: their own field universe only.
        _ => profile.is_queryable_field(field_name) || profile.is_queryable_field(&lower),
    }
}

/// Suggestion candidates, most useful first: the profile's default triage
/// columns, then its priority fields, then the whole universe.
fn suggestion_candidates(profile: &dyn SchemaProfile) -> Vec<&str> {
    let mut out: Vec<&str> = Vec::new();
    out.extend(profile.default_table_fields().iter().copied());
    out.extend(profile.priority_fields().iter().copied());
    out.extend(profile.fields().iter().map(|f| f.name));
    out
}

/// Format one unknown-field error. Starts with `Unknown field '<name>'` — the
/// editor's linter underlines the first quoted token.
fn unknown_field_message(field_name: &str, dataset: Dataset, profile: &dyn SchemaProfile) -> String {
    let candidates = suggestion_candidates(profile);
    let mut suggestions = suggest_similar_fields_in(field_name, candidates.iter().copied(), MAX_SUGGESTIONS);
    let lead = if suggestions.is_empty() {
        // Nothing close: show the dataset's main fields instead.
        suggestions = profile
            .default_table_fields()
            .iter()
            .take(MAX_SUGGESTIONS)
            .map(|s| s.to_string())
            .collect();
        "Available fields include"
    } else {
        "Did you mean"
    };
    let scope = match dataset {
        Dataset::Logs => match profile.id() {
            SchemaId::Ocsf => " in the OCSF schema".to_string(),
            _ => String::new(),
        },
        other => format!(" on dataset={}", dataset_name(other)),
    };
    if suggestions.is_empty() {
        return format!("Unknown field '{field_name}'{scope}.");
    }
    let list = suggestions
        .iter()
        .map(|s| format!("'{s}'"))
        .collect::<Vec<_>>()
        .join(", ");
    let end = if lead == "Did you mean" { "?" } else { "." };
    format!("Unknown field '{field_name}'{scope}. {lead} {list}{end}")
}

/// Result of the field check: `errors` make the query invalid (and the editors
/// block Save); `warnings` are advisory.
#[derive(Debug, Default)]
pub(crate) struct FieldCheck {
    pub errors: Vec<String>,
    pub warnings: Vec<String>,
}

/// A UDM name that a logs query on an OCSF tenant cannot read (no OCSF mapping
/// and no alias). The pre-NAN-5275 validator accepted every UDM name on every
/// schema, so existing rules may carry one; it is a WARNING, never an error, so
/// such a rule can still be edited and saved. Suggestions are OCSF paths only.
fn unmapped_udm_warning(field_name: &str, profile: &dyn SchemaProfile) -> String {
    let candidates = suggestion_candidates(profile);
    let suggestions =
        suggest_similar_fields_in(field_name, candidates.iter().copied(), MAX_SUGGESTIONS);
    let base = format!(
        "Field '{field_name}' has no OCSF mapping on this tenant and reads an empty value."
    );
    if suggestions.is_empty() {
        return format!("{base} Use an OCSF field path instead.");
    }
    let list = suggestions
        .iter()
        .map(|s| format!("'{s}'"))
        .collect::<Vec<_>>()
        .join(", ");
    format!("{base} Did you mean {list}?")
}

/// Unknown-field errors for `referenced`, judged against the schema the query
/// runs on (`dataset` + the tenant log profile).
#[cfg(test)]
pub(crate) fn unknown_field_errors(
    referenced: &[String],
    derived_fields: &HashSet<String>,
    dataset: Dataset,
    tenant_profile: &std::sync::Arc<dyn SchemaProfile>,
) -> Vec<String> {
    check_fields(referenced, derived_fields, dataset, tenant_profile).errors
}

/// Field check for `referenced`, judged against the schema the query runs on
/// (`dataset` + the tenant log profile).
pub(crate) fn check_fields(
    referenced: &[String],
    derived_fields: &HashSet<String>,
    dataset: Dataset,
    tenant_profile: &std::sync::Arc<dyn SchemaProfile>,
) -> FieldCheck {
    let profile = dataset_profile(dataset, tenant_profile);
    let mut out = FieldCheck::default();
    for field_name in referenced {
        let lower = field_name.to_lowercase();
        if KEYWORDS.contains(&lower.as_str())
            || COMMAND_PARAMS.contains(&lower.as_str())
            || derived_fields.contains(&lower)
        {
            continue;
        }
        if is_known(field_name, dataset, profile.as_ref()) {
            continue;
        }
        if dataset == Dataset::Logs
            && profile.id() == SchemaId::Ocsf
            && is_known_udm_log_field(field_name, &lower, profile.as_ref())
        {
            out.warnings.push(unmapped_udm_warning(field_name, profile.as_ref()));
            continue;
        }
        out.errors.push(unknown_field_message(field_name, dataset, profile.as_ref()));
    }
    out
}

#[cfg(test)]
#[path = "field_check_tests.rs"]
mod field_check_tests;
