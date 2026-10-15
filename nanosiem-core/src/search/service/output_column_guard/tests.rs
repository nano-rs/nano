// SPDX-License-Identifier: AGPL-3.0-or-later

//! NAN-2373 regression tests for the output-column guard.
//!
//! The defect these lock down: `| prevalence enrich=true | where host_count < 10`
//! returned 200 with zero rows on the lake because the prevalence stage emitted
//! none of its output columns, so the threshold compared against a column that
//! did not exist. A rule of that shape can never fire and never errors.

use super::{
    declared_output_columns, missing_declared_columns, missing_output_column_warning,
    validate_declared_output_column_references,
};
use crate::query::parse_query;

fn guard(query: &str) -> Result<(), String> {
    let parsed = parse_query(query).expect("query parses");
    validate_declared_output_column_references(&parsed).map_err(|error| error.to_string())
}

/// THE regression: a threshold on a column no stage produces must not be
/// silently indistinguishable from a legitimate zero-match query.
#[test]
fn threshold_on_never_produced_column_is_rejected_not_silently_empty() {
    let error = guard("class_uid=1007 | where host_count < 10").expect_err("must be rejected");
    assert!(
        error.contains("host_count") && error.contains("no earlier stage"),
        "error must name the column and the missing producer: {error}"
    );
}

#[test]
fn threshold_after_the_producing_stage_is_accepted() {
    guard("class_uid=1007 | prevalence enrich=true window=30d | where host_count < 10")
        .expect("prevalence enrich=true declares host_count");
}

/// False-positive guard: every dynamically produced column must still resolve.
#[test]
fn dynamically_produced_columns_are_not_rejected() {
    for query in [
        // stats alias
        "class_uid=1007 | stats dc(device.hostname) as host_count by file.name | where host_count < 10",
        // eval
        "class_uid=1007 | eval host_count=1 | where host_count > 0",
        // rename
        "class_uid=1007 | stats count as total by file.name | rename total as host_count | where host_count < 10",
        // runtime-loaded output schema
        "class_uid=1007 | inputlookup url=\"https://example.test/f.csv\" | where host_count < 10",
        // AI stage declares its own columns
        "class_uid=1007 | ai prompt=\"triage\" | where ai_confidence > 0.5",
    ] {
        guard(query).unwrap_or_else(|error| panic!("{query} must be accepted: {error}"));
    }
}

/// Only decoration-owned names are policed — ordinary event fields keep the
/// existing permissive validation behaviour.
#[test]
fn ordinary_field_thresholds_are_untouched() {
    guard("class_uid=1007 | where severity_id > 2").expect("plain event field");
    guard("class_uid=1007 | where some_unmapped_thing < 10").expect("unknown field stays lenient");
}

#[test]
fn prevalence_without_enrich_declares_nothing() {
    let parsed = parse_query("class_uid=1007 | prevalence hash_prevalence < 5").unwrap();
    let crate::query::Query::Piped { command, .. } = &parsed else {
        panic!("piped query");
    };
    assert!(declared_output_columns(command).is_none());
}

#[test]
fn prevalence_enrich_declares_its_output_columns() {
    let parsed = parse_query("class_uid=1007 | prevalence enrich=true").unwrap();
    let crate::query::Query::Piped { command, .. } = &parsed else {
        panic!("piped query");
    };
    let (stage, columns) = declared_output_columns(command).expect("enrich declares columns");
    assert_eq!(stage, "prevalence");
    assert!(columns.iter().any(|column| column == "host_count"));
    assert!(columns.iter().any(|column| column == "is_rare"));
}

/// The runtime half: rows that came back without the declared columns are
/// reported, and rows that carry them are not.
#[test]
fn missing_declared_columns_detects_the_silent_no_op() {
    let declared = vec!["host_count".to_string(), "is_rare".to_string()];
    let undecorated = vec![
        serde_json::json!({"class_uid": 1007, "actor": {"process": {"name": "notepad.exe"}}}),
        serde_json::json!({"class_uid": 1007}),
    ];
    assert_eq!(
        missing_declared_columns(&undecorated, &declared),
        vec!["host_count".to_string(), "is_rare".to_string()]
    );

    let decorated = vec![
        serde_json::json!({"class_uid": 1007, "host_count": 3, "is_rare": true}),
        serde_json::json!({"class_uid": 1007}),
    ];
    assert!(missing_declared_columns(&decorated, &declared).is_empty());
}

#[test]
fn empty_result_sets_make_no_claim() {
    assert!(missing_declared_columns(&[], &["host_count".to_string()]).is_empty());
}

#[test]
fn warning_names_the_stage_and_every_missing_column() {
    let message = missing_output_column_warning(
        "prevalence",
        &["host_count".to_string(), "is_rare".to_string()],
    );
    assert!(message.contains("`prevalence`"));
    assert!(message.contains("`host_count`"));
    assert!(message.contains("`is_rare`"));
}

/// The guard must run on EVERY search path, not just the lake one: it is wired
/// into `validate_query_field_names`, which core_search / streaming / explain
/// all call after parse.
#[test]
fn guard_is_wired_into_the_shared_search_validation() {
    let parsed = parse_query("class_uid=1007 | where host_count < 10").unwrap();
    assert!(
        crate::search::service::validate_query_field_names(
            &parsed,
            &crate::schema::OcsfProfile::lake_1_9()
        )
        .is_err(),
        "shared validation must reject a threshold on a never-produced column"
    );
    let with_producer =
        parse_query("class_uid=1007 | prevalence enrich=true | where host_count < 10").unwrap();
    crate::search::service::validate_query_field_names(
        &with_producer,
        &crate::schema::OcsfProfile::lake_1_9(),
    )
    .expect("the same query with its producing stage stays valid");
}
