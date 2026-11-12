// SPDX-License-Identifier: AGPL-3.0-or-later

//! NAN-5271 #28: rule-repository coverage judged against a per-source field
//! census, on both schemas. Before the fix every source stored an empty field
//! set, so a UDM rule naming any field read "none" and an OCSF rule (whose
//! paths were never extracted) read "full" regardless of the telemetry.

use super::*;
use crate::rule_repository::npl_parser::extract_required_fields;
use crate::schema::{OcsfProfile, UdmProfile};

fn rule(fields: &[&str], source_types: &[&str]) -> RepositoryRule {
    let now = chrono::Utc::now();
    RepositoryRule {
        id: uuid::Uuid::now_v7(),
        repository_id: uuid::Uuid::now_v7(),
        file_path: "rules/example.yml".to_string(),
        file_sha: None,
        raw_content: String::new(),
        title: Some("Example".to_string()),
        description: None,
        severity: Some("high".to_string()),
        mitre_tactics: None,
        mitre_techniques: None,
        tags: None,
        requires_fields: (!fields.is_empty())
            .then(|| fields.iter().map(|f| (*f).to_string()).collect()),
        requires_source_types: (!source_types.is_empty())
            .then(|| source_types.iter().map(|s| (*s).to_string()).collect()),
        conversion_status: "success".to_string(),
        converted_npl: None,
        conversion_confidence: None,
        conversion_warnings: None,
        conversion_field_mappings: None,
        coverage_status: None,
        coverage_missing_fields: None,
        created_at: now,
        updated_at: now,
    }
}

fn inventory(entries: &[(&str, &[&str])]) -> HashMap<String, HashSet<String>> {
    entries
        .iter()
        .map(|(st, keys)| {
            (
                (*st).to_string(),
                keys.iter().map(|k| (*k).to_string()).collect(),
            )
        })
        .collect()
}

fn check(
    profile: &dyn SchemaProfile,
    inv: &HashMap<String, HashSet<String>>,
    r: &RepositoryRule,
) -> CoverageResult {
    let scope = ScopeSet::unrestricted();
    check_rule_coverage_in(profile, inv, r, &LiveInventoryAccess::Scoped(&scope))
}

// ---------------------------------------------------------------- UDM

#[test]
fn udm_rule_with_every_field_present_is_full() {
    let inv = inventory(&[("windows_sysmon", &["process_name", "command_line", "src_ip"])]);
    let r = rule(&["process_name", "command_line"], &["windows_sysmon"]);
    let c = check(&UdmProfile::new(), &inv, &r);
    assert_eq!(c.status, "full");
    assert!(c.missing_fields.is_empty());
}

#[test]
fn udm_rule_with_some_fields_present_is_partial() {
    let inv = inventory(&[("windows_sysmon", &["process_name"])]);
    let r = rule(&["process_name", "parent_command_line"], &["windows_sysmon"]);
    let c = check(&UdmProfile::new(), &inv, &r);
    assert_eq!(c.status, "partial");
    assert_eq!(c.missing_fields, vec!["parent_command_line".to_string()]);
    assert_eq!(c.available_fields, vec!["process_name".to_string()]);
}

#[test]
fn udm_rule_with_no_field_present_is_none() {
    let inv = inventory(&[("windows_sysmon", &["src_ip"])]);
    let r = rule(&["process_name", "command_line"], &["windows_sysmon"]);
    let c = check(&UdmProfile::new(), &inv, &r);
    assert_eq!(c.status, "none");
    assert_eq!(c.missing_fields.len(), 2);
}

/// Sigma-era spellings and `ext` keys meet the census through the same keys.
#[test]
fn udm_sigma_names_and_ext_keys_resolve_to_census_keys() {
    let inv = inventory(&[("edr", &["command_line", "ext:signer"])]);
    let r = rule(&["CommandLine", "ext.signer"], &[]);
    let c = check(&UdmProfile::new(), &inv, &r);
    assert_eq!(c.status, "full", "{c:?}");
}

/// Only the sources the rule targets count toward its fields.
#[test]
fn fields_on_an_unrelated_source_do_not_count() {
    let inv = inventory(&[
        ("windows_sysmon", &["src_ip"]),
        ("linux_auditd", &["process_name"]),
    ]);
    let r = rule(&["process_name"], &["windows_sysmon"]);
    assert_eq!(check(&UdmProfile::new(), &inv, &r).status, "none");
}

// ---------------------------------------------------------------- OCSF

#[test]
fn ocsf_rule_with_every_path_present_is_full() {
    let inv = inventory(&[(
        "windows_sysmon",
        &["class_uid", "process.cmd_line", "actor.process.cmd_line"],
    )]);
    let r = rule(&["class_uid", "process.cmd_line"], &["windows_sysmon"]);
    let c = check(&OcsfProfile::new(), &inv, &r);
    assert_eq!(c.status, "full");
}

/// A UDM-named field in an OCSF tenant is judged at its OCSF column.
#[test]
fn ocsf_resolves_udm_names_onto_ocsf_columns() {
    let inv = inventory(&[("zeek_conn", &["src_endpoint.ip"])]);
    let r = rule(&["src_ip"], &["zeek_conn"]);
    assert_eq!(check(&OcsfProfile::new(), &inv, &r).status, "full");
}

#[test]
fn ocsf_rule_with_some_paths_present_is_partial() {
    let inv = inventory(&[("windows_sysmon", &["class_uid", "process.cmd_line"])]);
    let r = rule(
        &["process.cmd_line", "actor.process.cmd_line"],
        &["windows_sysmon"],
    );
    let c = check(&OcsfProfile::new(), &inv, &r);
    assert_eq!(c.status, "partial");
    assert_eq!(c.missing_fields, vec!["actor.process.cmd_line".to_string()]);
}

#[test]
fn ocsf_rule_with_no_path_present_is_none() {
    let inv = inventory(&[("apache_http_server", &["http_request.url.hostname"])]);
    let r = rule(&["process.cmd_line"], &["apache_http_server"]);
    assert_eq!(check(&OcsfProfile::new(), &inv, &r).status, "none");
}

/// A spill key is judged against the `unmapped` census under OCSF.
#[test]
fn ocsf_unmapped_keys_are_judged_against_the_spill_census() {
    let inv = inventory(&[("vendor", &["class_uid", "unmapped:custom_flag"])]);
    let present = rule(&["unmapped.custom_flag"], &[]);
    let absent = rule(&["unmapped.other"], &[]);
    assert_eq!(check(&OcsfProfile::new(), &inv, &present).status, "full");
    assert_eq!(check(&OcsfProfile::new(), &inv, &absent).status, "none");
}

/// When the spill scan failed the spill is unknown, so no spill key is missing.
#[test]
fn a_failed_spill_scan_never_reports_spill_keys_missing() {
    let inv = inventory(&[("vendor", &["class_uid", "unmapped:*"])]);
    let r = rule(&["unmapped.anything"], &[]);
    assert_eq!(check(&OcsfProfile::new(), &inv, &r).status, "full");
}

// ------------------------------------------------------------ no census

/// The pre-fix inventory shape (every source with an empty set) must not turn
/// every field-bearing rule into "none" on either schema.
#[test]
fn no_census_keeps_rules_full_on_both_schemas() {
    let inv = inventory(&[("windows_sysmon", &[]), ("apache_http_server", &[])]);
    let udm = rule(&["process_name", "command_line"], &["windows_sysmon"]);
    let ocsf = rule(&["process.cmd_line", "class_uid"], &["windows_sysmon"]);
    for (profile, r) in [
        (&UdmProfile::new() as &dyn SchemaProfile, &udm),
        (&OcsfProfile::new() as &dyn SchemaProfile, &ocsf),
    ] {
        let c = check(profile, &inv, r);
        assert_eq!(c.status, "full", "{c:?}");
        assert!(c.missing_fields.is_empty());
    }
}

#[test]
fn an_empty_inventory_keeps_rules_full() {
    let r = rule(&["process_name"], &[]);
    assert_eq!(check(&UdmProfile::new(), &HashMap::new(), &r).status, "full");
}

/// A known census on one relevant source is judged; an unknown one is ignored.
#[test]
fn unknown_census_sources_do_not_vote() {
    let inv = inventory(&[("sysmon_a", &[]), ("sysmon_b", &["process_name"])]);
    let r = rule(&["process_name", "command_line"], &["sysmon"]);
    let c = check(&UdmProfile::new(), &inv, &r);
    assert_eq!(c.status, "partial");
    assert_eq!(c.missing_fields, vec!["command_line".to_string()]);
}

/// The aggregate's `source_types_with_field` reads the census keys too.
#[test]
fn aggregate_lists_sources_carrying_a_missing_field() {
    let inv = inventory(&[
        ("windows_sysmon", &["src_endpoint.ip"]),
        ("edr", &["process.cmd_line"]),
    ]);
    let rules = [rule(&["command_line"], &["windows_sysmon"])];
    let profile = OcsfProfile::new();
    let analysis = analyze_coverage_with(&profile, &rules, &CoverageFilter::default(), &inv, |r| {
        check(&profile, &inv, r)
    });
    assert_eq!(analysis.no_coverage, 1);
    assert_eq!(analysis.most_missing_fields[0].field, "command_line");
    assert_eq!(
        analysis.most_missing_fields[0].source_types_with_field,
        vec!["edr".to_string()]
    );
}

// ------------------------------------------------------------ extraction

#[test]
fn ocsf_rule_paths_are_extracted() {
    let q = r#"metadata.log_source="windows_sysmon"
| where class_uid=1007 AND process.cmd_line="*-enc*" AND actor.process.file.name IN ("cmd.exe")
| stats count by device.hostname, actor.user.name"#;
    let fields = extract_required_fields(q);
    for f in [
        "class_uid",
        "process.cmd_line",
        "actor.process.file.name",
        "device.hostname",
        "actor.user.name",
    ] {
        assert!(fields.contains(&f.to_string()), "{f} missing from {fields:?}");
    }
    assert!(!fields.contains(&"metadata.log_source".to_string()));
}

#[test]
fn udm_rule_gains_no_ocsf_fields_and_quoted_values_are_ignored() {
    let q = r#"source_type=windows_sysmon | where process_name="a.b=c" AND command_line="x""#;
    let mut fields = extract_required_fields(q);
    fields.sort();
    assert_eq!(fields, vec!["command_line".to_string(), "process_name".to_string()]);
}

// ---------------------------------------------------------------- SQL

#[test]
fn census_sql_is_time_bounded_single_where_and_escaped() {
    let now = chrono::Utc::now();
    let [(start, end), _] = field_census::census_windows(now);
    let sql = field_census::build_column_census_sql(
        "ocsf_logs_distributed",
        &["process.cmd_line".to_string(), "class_uid".to_string()],
        "o'brien",
        start,
        end,
    )
    .unwrap();
    assert!(sql.contains("WHERE timestamp BETWEEN '"));
    assert!(!sql.to_uppercase().contains("PREWHERE"));
    assert!(sql.contains("source_type = 'o''brien'"), "{sql}");
    assert!(
        sql.contains(&format!(
            "{} AS __census_0",
            crate::sql_hygiene::quote_identifier("process.cmd_line")
        )),
        "{sql}"
    );
    assert!(sql.contains("LIMIT 5000"));
    assert!(sql.contains("max_rows_to_read"));
    assert!(field_census::build_column_census_sql("t", &[], "s", start, end).is_none());
}

#[test]
fn census_column_inventory_excludes_routing_and_json_columns() {
    let sql = field_census::build_census_columns_sql("ocsf_logs");
    assert!(sql.contains("table = 'ocsf_logs'"));
    assert!(sql.contains("'source_type'"));
    assert!(sql.contains("type NOT LIKE 'JSON%'"));
}
