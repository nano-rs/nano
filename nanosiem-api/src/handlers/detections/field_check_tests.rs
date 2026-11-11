// SPDX-License-Identifier: AGPL-3.0-or-later

//! NAN-5275: the detection validator's field check is schema- and
//! dataset-aware.

use std::collections::HashSet;
use std::sync::Arc;

use nanosiem_core::query::Dataset;
use nanosiem_core::schema::{profile_for_id, SchemaId, SchemaProfile};

use super::{check_fields, parse_dataset, referenced_fields, unknown_field_errors};

/// The seeded `accumulated_risk_threshold_exceeded` rule's query (enterprise
/// migration 9000033, `RiskNotableConfig::default_rule_query`).
const SEEDED_RISK_QUERY: &str = "* | where score_24h > 500 or score_7d > 1000 | table entity, entity_type, score_24h, score_7d, distinct_rules_7d, last_rule_name";

fn profile(id: SchemaId) -> Arc<dyn SchemaProfile> {
    profile_for_id(id)
}

fn check(query: &str, dataset: Dataset, tenant: SchemaId) -> Vec<String> {
    let derived: HashSet<String> = nanosiem_core::parse_query(query)
        .map(|q| nanosiem_core::collect_derived_fields(&q))
        .unwrap_or_default();
    unknown_field_errors(&referenced_fields(query), &derived, dataset, &profile(tenant))
}

// --- dataset=risk -----------------------------------------------------------

#[test]
fn seeded_risk_rule_validates_on_risk_dataset() {
    for tenant in [SchemaId::Udm, SchemaId::Ocsf] {
        let errors = check(SEEDED_RISK_QUERY, Dataset::Risk, tenant);
        assert!(errors.is_empty(), "{tenant:?}: {errors:?}");
    }
}

#[test]
fn seeded_risk_query_is_still_flagged_on_logs() {
    // The bug: the editor validated a dataset=risk rule as a logs query.
    let errors = check(SEEDED_RISK_QUERY, Dataset::Logs, SchemaId::Ocsf);
    assert!(
        errors.iter().any(|e| e.starts_with("Unknown field 'score_24h'")),
        "{errors:?}"
    );
}

#[test]
fn risk_dataset_rejects_log_fields_and_suggests_risk_columns() {
    let errors = check("score_24hh > 5 or src_ip = \"1.2.3.4\"", Dataset::Risk, SchemaId::Ocsf);
    assert_eq!(errors.len(), 2, "{errors:?}");
    let typo = errors.iter().find(|e| e.contains("'score_24hh'")).unwrap();
    assert!(typo.contains("on dataset=risk"), "{typo}");
    assert!(typo.contains("'score_24h'"), "{typo}");
    let log_field = errors.iter().find(|e| e.contains("'src_ip'")).unwrap();
    // Nothing close: the risk grain's main columns are offered instead.
    assert!(log_field.contains("'entity'"), "{log_field}");
    assert!(!log_field.contains("'dest_ip'"), "{log_field}");
}

// --- OCSF tenant, logs dataset ---------------------------------------------

#[test]
fn ocsf_suggestions_are_ocsf_fields_not_udm() {
    let errors = check("src_endpoint.ipp = \"10.0.0.1\"", Dataset::Logs, SchemaId::Ocsf);
    assert_eq!(errors.len(), 1, "{errors:?}");
    let msg = &errors[0];
    assert!(msg.starts_with("Unknown field 'src_endpoint.ipp' in the OCSF schema"), "{msg}");
    assert!(msg.contains("'src_endpoint.ip'"), "{msg}");
    for udm in ["'src_ip'", "'dest_ip'", "'src_host'"] {
        assert!(!msg.contains(udm), "OCSF suggestion leaked UDM {udm}: {msg}");
    }
}

#[test]
fn ocsf_accepts_promoted_columns_and_the_alias_layer() {
    let q = "src_endpoint.ip = \"10.0.0.1\" src_ip = \"10.0.0.1\" user = \"bob\" \
             source_type = \"windows_sysmon\" unmapped.error_code = 5 \
             event.src_endpoint.ip = \"10.0.0.1\" risk_score > 10 rule_name = \"x\"";
    let errors = check(q, Dataset::Logs, SchemaId::Ocsf);
    assert!(errors.is_empty(), "{errors:?}");
}

#[test]
fn ocsf_dotted_field_is_captured_whole() {
    // Capturing only `ip` used to raise a false "Unknown field 'ip'".
    assert_eq!(
        referenced_fields("actor.process.cmd_line = \"x\""),
        vec!["actor.process.cmd_line".to_string()]
    );
}

#[test]
fn ocsf_flags_a_name_with_no_ocsf_meaning() {
    let errors = check("totally_bogus_field = 1", Dataset::Logs, SchemaId::Ocsf);
    assert_eq!(errors.len(), 1, "{errors:?}");
    assert!(!errors[0].contains("'src_ip'"), "{}", errors[0]);
}

// --- UDM tenant, logs dataset (unchanged behaviour) -------------------------

#[test]
fn udm_logs_validation_is_unchanged_for_known_fields() {
    let q = "src_ip = \"10.0.0.1\" process_name = \"cmd.exe\" enriched_src_country = \"US\" \
             ext.error_code = 5 | stats count by src_ip | where count > 3";
    let errors = check(q, Dataset::Logs, SchemaId::Udm);
    assert!(errors.is_empty(), "{errors:?}");
}

#[test]
fn udm_unknown_field_suggests_close_udm_fields() {
    let errors = check("src_ipp = \"10.0.0.1\"", Dataset::Logs, SchemaId::Udm);
    assert_eq!(errors.len(), 1, "{errors:?}");
    assert!(errors[0].contains("'src_ip'"), "{}", errors[0]);
}

// --- dataset parsing ---------------------------------------------------------

#[test]
fn dataset_parsing() {
    assert_eq!(parse_dataset(None).unwrap(), Dataset::Logs);
    assert_eq!(parse_dataset(Some("")).unwrap(), Dataset::Logs);
    assert_eq!(parse_dataset(Some("risk")).unwrap(), Dataset::Risk);
    assert_eq!(parse_dataset(Some("spans")).unwrap(), Dataset::Spans);
    assert!(parse_dataset(Some("riskk")).is_err());
}

#[test]
fn spans_dataset_accepts_attribute_paths() {
    let errors = check("http.method = \"GET\"", Dataset::Spans, SchemaId::Ocsf);
    assert!(errors.is_empty(), "{errors:?}");
}

// --- review follow-ups -------------------------------------------------------

/// Short UDM names / `*_unified` columns the product must never SUGGEST on
/// OCSF (they stay accepted as aliases).
const FORBIDDEN_OCSF_SUGGESTIONS: &[&str] = &[
    "'user'", "'src_host'", "'dest_host'", "'process_name'", "'command_line'",
    "'src_ip'", "'dest_ip'", "'src_user'", "'dest_user'", "'file_hash'",
    "'process_path'", "'parent_command_line'", "_unified'",
];

#[test]
fn ocsf_suggestions_never_offer_udm_aliases() {
    for typo in [
        "usr", "src_hst", "proces_name", "comand_line", "dest_hostt", "srcip", "src_ipp",
        "user_nam", "dest_ipp", "src_usr", "file_hsh", "cmd_lin", "process_nme",
    ] {
        let out = check_fields(&[typo.to_string()], &HashSet::new(), Dataset::Logs, &profile(SchemaId::Ocsf));
        for msg in out.errors.iter().chain(out.warnings.iter()) {
            for bad in FORBIDDEN_OCSF_SUGGESTIONS {
                assert!(!msg.contains(bad), "{typo}: suggested {bad}: {msg}");
            }
        }
    }
}

#[test]
fn ocsf_unmapped_udm_name_is_a_warning_not_an_error() {
    // Accepted by the pre-NAN-5275 validator on every schema; an existing rule
    // that uses it must stay saveable.
    let out = check_fields(
        &["dest_nt_host".to_string()],
        &HashSet::new(),
        Dataset::Logs,
        &profile(SchemaId::Ocsf),
    );
    assert!(out.errors.is_empty(), "{:?}", out.errors);
    assert_eq!(out.warnings.len(), 1, "{:?}", out.warnings);
    assert!(out.warnings[0].contains("no OCSF mapping"), "{}", out.warnings[0]);
    for bad in FORBIDDEN_OCSF_SUGGESTIONS {
        assert!(!out.warnings[0].contains(bad), "{}", out.warnings[0]);
    }
    // UDM tenant: still plainly valid.
    let udm = check_fields(&["dest_nt_host".to_string()], &HashSet::new(), Dataset::Logs, &profile(SchemaId::Udm));
    assert!(udm.errors.is_empty() && udm.warnings.is_empty(), "{udm:?}");
}

#[test]
fn quoted_values_are_not_read_as_field_comparisons() {
    // Shipped content: `process.cmd_line CONTAINS "/LogFile="` and
    // `"key=clear"` used to raise "Unknown field 'LogFile'" / "'key'".
    let q = r#"process.cmd_line CONTAINS "/LogFile=" OR process.cmd_line CONTAINS 'key=clear' OR x CONTAINS "a\"b=c" | where class_uid=1007"#;
    assert_eq!(
        referenced_fields(q),
        vec!["class_uid".to_string()],
    );
}
